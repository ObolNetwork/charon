// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"bytes"
	"context"
	"os"
	"slices"
	"strconv"
	"strings"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/core"
)

// proposerConfigEditCmd is the command changing the proposer config cluster-wide.
const proposerConfigEditCmd = "charon alpha edit proposer-config"

// loadProposerConfig loads the validator client proposer config file on start, writing genesis if it is
// absent, verifying it and re-rendering it for this node. Only a file of another
// cluster and a genesis needed but underivable return errors; other failures are logged and a document returned.
func loadProposerConfig(ctx context.Context, conf Config, lock cluster.Lock, nodeIdx cluster.NodeIdx,
	feeRecipientFunc func(core.PubKey) string, gloasActive func() bool,
) (proposerconfig.Document, error) {
	// Genesis is only derived when needed, a valid signed file never depends on it.
	genesis := func() (proposerconfig.Document, error) {
		return ProposerConfigGenesis(lock, conf.ProposerConfigSeed, feeRecipientFunc)
	}

	if conf.TestConfig.Lock != nil {
		// In-memory test lock, there is no cluster directory holding the file.
		return genesis()
	}

	path := conf.ProposerConfigFile
	ctx = log.WithCtx(ctx, z.Str("path", path))

	// unusable leaves the file untouched for the operator to inspect, charon uses genesis meanwhile.
	unusable := func(err error) (proposerconfig.Document, error) {
		log.Error(ctx, "Failed loading proposer config file, using one derived from the lock and flags; fix it or delete it to regenerate", err)

		gen, err := genesis()
		if err != nil {
			return proposerconfig.Document{}, err
		}

		setProposerConfigGauges(gen, false)

		return gen, nil
	}

	doc, err := proposerconfig.Load(path, lock, nodeIdx)
	if errors.Is(err, proposerconfig.ErrLockHashMismatch) {
		return proposerconfig.Document{}, errors.Wrap(err, "proposer config file belongs to another cluster (after a lock-changing edit, use vc-config/ from its output directory)")
	} else if errors.Is(err, proposerconfig.ErrNotFound) {
		return writeProposerConfigGenesis(ctx, path, lock, nodeIdx, genesis, gloasActive)
	} else if err != nil {
		return unusable(err)
	}

	// Content charon cannot parse is as unusable as an undecodable file, verified or not.
	if _, err := newProposerConfigSnapshot(doc); err != nil {
		return unusable(err)
	}

	err = proposerconfig.Verify(doc, lock)
	valid := err == nil
	setProposerConfigGauges(doc, valid)

	if valid {
		log.Info(ctx, "Loaded proposer config file", revisionFields(doc)...)
	} else {
		// The validator client uses the file regardless, so charon does too.
		log.Error(ctx, "Invalid proposer config file, using it anyway", err, z.U64("revision", doc.Revision))
	}

	if doc.Revision == 0 {
		warnProposerConfigDrift(ctx, lock, doc, genesis)
		warnProposerConfigUnsigned(ctx, gloasActive)
	} else if valid {
		warnProposerConfigFlagsIgnored(ctx, lock, doc, conf.ProposerConfigSeed)
	}

	// Never rewrite an invalid file, it may be a newer format or evidence of a hand edit.
	if valid {
		rerenderProposerConfig(ctx, path, doc, lock, nodeIdx)
	}

	return doc, nil
}

// writeProposerConfigGenesis writes genesis to the absent file, returning it even if the write fails.
func writeProposerConfigGenesis(ctx context.Context, path string, lock cluster.Lock, nodeIdx cluster.NodeIdx,
	genesis func() (proposerconfig.Document, error), gloasActive func() bool,
) (proposerconfig.Document, error) {
	gen, err := genesis()
	if err != nil {
		return proposerconfig.Document{}, err
	}

	err = proposerconfig.Write(path, gen, lock, nodeIdx)
	if err != nil {
		log.Error(ctx, "Failed writing proposer config file, VC proposer settings must be configured manually", err)
		setProposerConfigGauges(gen, false)

		return gen, nil
	}

	setProposerConfigGauges(gen, true)
	log.Info(ctx, "Generated proposer config file for validator clients", revisionFields(gen)...)
	warnProposerConfigUnsigned(ctx, gloasActive)

	return gen, nil
}

// warnProposerConfigDrift warns once if the revision 0 file differs from genesis; the file wins
// since the flags only seed it.
func warnProposerConfigDrift(ctx context.Context, lock cluster.Lock, doc proposerconfig.Document, genesis func() (proposerconfig.Document, error)) {
	gen, err := genesis()
	if err != nil {
		log.Warn(ctx, "Skipped checking the proposer config file against the lock and flags", err)
		return
	}

	lines := proposerconfig.FormatDiffs(proposerconfig.Diff(lock, doc.Content, gen.Content))
	if len(lines) == 0 {
		return
	}

	log.Warn(ctx, "Proposer config file differs from the lock and flags, using the file; change it with "+proposerConfigEditCmd, nil,
		DiffSummaryFields(lines)...)
}

// DiffSummaryFields returns the log fields summarising diff lines: their count and the first few.
func DiffSummaryFields(lines []string) []z.Field {
	const maxExamples = 3

	return []z.Field{
		z.Int("differences", len(lines)),
		z.Str("examples", strings.Join(lines[:min(len(lines), maxExamples)], "; ")),
	}
}

// GenesisFeeRecipientFunc returns the fee recipients the genesis proposer config is derived from, as on charon run
// start: the builder registration service over the lock's registrations and the overrides file, so a registration
// override newer than the lock's wins. A validator without a lock registration keeps its lock fee recipient.
func GenesisFeeRecipientFunc(ctx context.Context, lock cluster.Lock, overridesFile string) (func(core.PubKey) string, error) {
	var (
		regs = make([]*eth2api.VersionedSignedValidatorRegistration, 0, len(lock.Validators))
		fees = make(map[core.PubKey]string, len(lock.Validators))
	)

	lockFees := lock.FeeRecipientAddresses()

	for i, val := range lock.Validators {
		pubkey, err := core.PubKeyFromBytes(val.PubKey)
		if err != nil {
			return nil, errors.Wrap(err, "core pubkey", z.Int("validator", i))
		}

		fees[pubkey] = lockFees[i]

		reg, err := val.Eth2Registration()
		if err != nil {
			reg = nil // Locks before v1.7 have no registrations, the service skips them.
		}

		regs = append(regs, reg)
	}

	svc, err := NewBuilderRegistrationService(ctx, overridesFile, eth2p0.Version(lock.ForkVersion), regs, fees, nil, lock.LockHash)
	if err != nil {
		return nil, err
	}

	return svc.FeeRecipient, nil
}

// ProposerConfigGenesis returns the unsigned revision 0 document: fee recipients from the effective builder
// registrations falling back to the lock, gas limit and builder from the seed flags.
func ProposerConfigGenesis(lock cluster.Lock, seed proposerconfig.Seed, feeRecipientFunc func(core.PubKey) string) (proposerconfig.Document, error) {
	lockFees := lock.FeeRecipientAddresses()
	fees := make([]string, 0, len(lock.Validators))

	for i, val := range lock.Validators {
		pubkey, err := core.PubKeyFromBytes(val.PubKey)
		if err != nil {
			return proposerconfig.Document{}, errors.Wrap(err, "core pubkey", z.Int("validator", i))
		}

		fee := feeRecipientFunc(pubkey)
		if fee == "" {
			fee = lockFees[i]
		}

		fees = append(fees, fee)
	}

	content, err := proposerconfig.NewContent(lock, fees, seed.GasLimit, seed.Builder())
	if err != nil {
		return proposerconfig.Document{}, errors.Wrap(err, "proposer config genesis")
	}

	return proposerconfig.Document{
		Version:  proposerconfig.Version,
		LockHash: lock.LockHash,
		Content:  content,
	}, nil
}

// proposerConfigSeedFlags maps the default config fields to the seeding flags setting them.
var proposerConfigSeedFlags = map[string]string{
	"default.gas_limit":                     "proposer-config-gas-limit",
	"default.builder.urls":                  "proposer-config-builder-urls",
	"default.builder.min_bid":               "proposer-config-builder-min-bid",
	"default.builder.boost_factor":          "proposer-config-builder-boost-factor",
	"default.builder.max_execution_payment": "proposer-config-builder-max-execution-payment",
}

// warnProposerConfigFlagsIgnored warns once if seeding flags the operator set differ from the signed document's defaults.
func warnProposerConfigFlagsIgnored(ctx context.Context, lock cluster.Lock, doc proposerconfig.Document, seed proposerconfig.Seed) {
	seeded := doc.Content
	seeded.DefaultConfig.GasLimit = strconv.FormatUint(seed.GasLimit, 10)
	seeded.DefaultConfig.Builder = seed.Builder()

	var flags []string

	for _, diff := range proposerconfig.Diff(lock, doc.Content, seeded) {
		flag, ok := proposerConfigSeedFlags[diff.Field]
		if ok && slices.Contains(seed.NonDefault, flag) {
			flags = append(flags, flag)
		}
	}

	if len(flags) == 0 {
		return
	}

	log.Warn(ctx, "Proposer config flags ignored, the cluster agreed on different values with "+proposerConfigEditCmd, nil,
		z.Str("flags", strings.Join(flags, ",")))
}

// warnProposerConfigUnsigned warns post-gloas that the file is unsigned.
func warnProposerConfigUnsigned(ctx context.Context, gloasActive func() bool) {
	if !gloasActive() {
		return
	}

	log.Warn(ctx, "Proposer config file is unsigned, agree on it cluster-wide with "+proposerConfigEditCmd, nil)
}

// rerenderProposerConfig rewrites the file if its rendering for this node differs from the document.
func rerenderProposerConfig(ctx context.Context, path string, doc proposerconfig.Document, lock cluster.Lock, nodeIdx cluster.NodeIdx) {
	want, err := proposerconfig.Render(doc, lock, nodeIdx)
	if err != nil {
		log.Warn(ctx, "Failed rendering proposer config file", err)
		return
	}

	current, err := os.ReadFile(path)
	if err == nil && bytes.Equal(current, want) {
		return
	}

	err = proposerconfig.Write(path, doc, lock, nodeIdx)
	if err != nil {
		log.Warn(ctx, "Failed rewriting proposer config file", err)
		return
	}

	log.Info(ctx, "Rewrote proposer config file for this node")
}

// revisionFields returns the log fields identifying the document's revision.
func revisionFields(doc proposerconfig.Document) []z.Field {
	fields := []z.Field{z.U64("revision", doc.Revision)}
	if len(doc.Signatures) > 0 {
		fields = append(fields, z.Any("signers", doc.SignerIndexes()))
	}

	hash, err := doc.Hash()
	if err == nil {
		fields = append(fields, z.Hex("revision_hash", hash[:]))
	}

	return fields
}

// setProposerConfigGauges sets the revision and invalid gauges for the loaded document.
func setProposerConfigGauges(doc proposerconfig.Document, valid bool) {
	proposerConfigRevisionGauge.Set(float64(doc.Revision))

	if valid {
		proposerConfigInvalidGauge.Set(0)
	} else {
		proposerConfigInvalidGauge.Set(1)
	}
}
