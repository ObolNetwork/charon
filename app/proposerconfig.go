// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"os"
	"path/filepath"
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

// newProposerConfigService returns the service of the validator client proposer config file, loading the file on
// start: the initial one is written if it is absent, a present one is verified. Only a file of another
// cluster and an initial config needed but underivable return errors; other failures are logged and a service returned.
func newProposerConfigService(ctx context.Context, conf Config, lock cluster.Lock, nodeIdx cluster.NodeIdx,
	feeRecipientFunc func(core.PubKey) string, gloasActive func() bool,
) (*proposerConfigService, error) {
	path := conf.ProposerConfigFile

	// The initial config is only derived when needed, a valid signed file never depends on it.
	initial := func() (proposerconfig.Document, error) {
		return InitialProposerConfig(lock, conf.ProposerConfigSeed, feeRecipientFunc)
	}

	// changes receives the file changes to reload, nil without a watcher.
	var changes <-chan struct{}

	// serve returns the service of the document, parsing its config once. verified says whether the document
	// passed verification: an unverified one is replaced by any verified file.
	serve := func(doc proposerconfig.Document, verified bool) (*proposerConfigService, error) {
		snap, err := newProposerConfigSnapshot(doc, verified)
		if err != nil {
			return nil, err
		}

		initBuilderConfigMetrics(snap.builder)

		s := &proposerConfigService{lock: lock, nodeIdx: nodeIdx, path: path, changes: changes}
		s.current.Store(snap)

		return s, nil
	}

	ctx = log.WithCtx(ctx, z.Str("path", path))

	if conf.TestConfig.Lock != nil {
		// In-memory test lock, there is no cluster directory holding the file.
		doc, err := initial()
		if err != nil {
			return nil, err
		}

		return serve(doc, true) // Unsigned revision 0 verifies.
	}

	// Watched before loading, so that a file replaced meanwhile is reloaded, in the directory the initial file is written into.
	err := os.MkdirAll(filepath.Dir(path), 0o755)
	if err != nil {
		log.Error(ctx, "Failed creating proposer config directory, changes need a restart", err)
	} else {
		changes, err = watchFile(ctx, path)
		if err != nil {
			log.Error(ctx, "Failed watching proposer config file, changes need a restart", err)
		}
	}

	// unusable leaves the file untouched for the operator to inspect, charon uses the initial config meanwhile.
	unusable := func(err error) (*proposerConfigService, error) {
		log.Error(ctx, "Failed loading proposer config file, using one derived from the lock and flags; fix it or delete it to regenerate", err)

		doc, err := initial()
		if err != nil {
			return nil, err
		}

		setProposerConfigGauges(doc, false)

		return serve(doc, true)
	}

	doc, err := proposerconfig.Load(path, lock, nodeIdx)
	if errors.Is(err, proposerconfig.ErrLockHashMismatch) {
		return nil, errors.Wrap(err, "proposer config file belongs to another cluster (after a lock-changing edit, use vc-config/ from its output directory)")
	} else if errors.Is(err, proposerconfig.ErrNotFound) {
		doc, err := writeInitialProposerConfig(ctx, path, lock, nodeIdx, initial, gloasActive)
		if err != nil {
			return nil, err
		}

		return serve(doc, true)
	} else if err != nil {
		return unusable(err)
	}

	err = proposerconfig.Verify(doc, lock)
	valid := err == nil

	// Config charon cannot parse is as unusable as an undecodable file, verified or not.
	s, serveErr := serve(doc, valid)
	if serveErr != nil {
		return unusable(serveErr)
	}

	setProposerConfigGauges(doc, valid)

	if valid {
		log.Info(ctx, "Loaded proposer config file", revisionFields(doc)...)
	} else {
		// The validator client uses the file regardless, so charon does too.
		log.Error(ctx, "Invalid proposer config file, using it anyway", err, z.U64("revision", doc.Revision))
	}

	// Unsigned, the flags seeded it: report where it differs from them.
	if doc.Revision == 0 {
		warnUnsignedProposerConfigDiffers(ctx, lock, doc, initial)
		warnUnsignedProposerConfigAfterGloas(ctx, gloasActive)
	}

	// Signed and verified: report the seeding flags it overrides.
	if doc.Revision > 0 && valid {
		warnSignedProposerConfigOverridesFlags(ctx, doc, conf.ProposerConfigSeed)
	}

	return s, nil
}

// writeInitialProposerConfig writes the initial config to the absent file, returning it even if the write fails.
func writeInitialProposerConfig(ctx context.Context, path string, lock cluster.Lock, nodeIdx cluster.NodeIdx,
	initial func() (proposerconfig.Document, error), gloasActive func() bool,
) (proposerconfig.Document, error) {
	doc, err := initial()
	if err != nil {
		return proposerconfig.Document{}, err
	}

	err = proposerconfig.Write(path, doc, lock, nodeIdx)
	if err != nil {
		log.Error(ctx, "Failed writing proposer config file", err)
		setProposerConfigGauges(doc, false)

		return doc, nil
	}

	setProposerConfigGauges(doc, true)
	log.Info(ctx, "Generated proposer config file for validator clients", revisionFields(doc)...)
	warnUnsignedProposerConfigAfterGloas(ctx, gloasActive)

	return doc, nil
}

// warnUnsignedProposerConfigDiffers warns once if the unsigned (revision 0) file differs from the initial config
// derived from the lock and flags; the file wins since the flags only seed it.
func warnUnsignedProposerConfigDiffers(ctx context.Context, lock cluster.Lock, doc proposerconfig.Document, initial func() (proposerconfig.Document, error)) {
	want, err := initial()
	if err != nil {
		log.Warn(ctx, "Skipped checking the proposer config file against the lock and flags", err)
		return
	}

	lines := proposerconfig.Diff(lock, doc.Config, want.Config)
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

// RegistrationFeeRecipientFunc returns the fee recipients the initial proposer config is derived from, as on charon run
// start: the builder registration service over the lock's registrations and the overrides file, so a registration
// override newer than the lock's wins. An invalid lock registration is an error, as on charon run.
func RegistrationFeeRecipientFunc(ctx context.Context, lock cluster.Lock, overridesFile string) (func(core.PubKey) string, error) {
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
			return nil, errors.Wrap(err, "convert builder registration", z.Int("validator", i))
		}

		regs = append(regs, reg)
	}

	svc, err := NewBuilderRegistrationService(ctx, overridesFile, eth2p0.Version(lock.ForkVersion), regs, fees, nil, lock.LockHash)
	if err != nil {
		return nil, err
	}

	return svc.FeeRecipient, nil
}

// InitialProposerConfig returns the unsigned revision 0 document: fee recipients from the effective builder
// registrations falling back to the lock, gas limit and builder from the seed flags.
func InitialProposerConfig(lock cluster.Lock, seed proposerconfig.Seed, feeRecipientFunc func(core.PubKey) string) (proposerconfig.Document, error) {
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

	cfg, err := proposerconfig.NewConfig(lock, fees, seed.GasLimit, seed.Builder())
	if err != nil {
		return proposerconfig.Document{}, errors.Wrap(err, "initial proposer config")
	}

	return proposerconfig.Document{
		Version:  proposerconfig.Version,
		LockHash: lock.LockHash,
		Config:   cfg,
	}, nil
}

// warnSignedProposerConfigOverridesFlags warns once if seeding flags the operator set differ from the signed file's
// defaults, logging both values; the signed file wins.
func warnSignedProposerConfigOverridesFlags(ctx context.Context, doc proposerconfig.Document, seed proposerconfig.Seed) {
	fileVals := proposerconfig.FlagValues(doc.Config.DefaultConfig)
	flagVals := proposerconfig.FlagValues(proposerconfig.Settings{GasLimit: strconv.FormatUint(seed.GasLimit, 10), Builder: seed.Builder()})

	show := func(flag string, vals []string) string {
		val := strings.Join(vals, ",")
		if flag == "proposer-config-builder-urls" {
			// Builder URLs may carry credentials, shown redacted as the URL flags are logged.
			val = proposerconfig.RedactURLs(vals)
		}

		if val == "" {
			return "none"
		}

		return val
	}

	var ignored []string

	for _, flag := range seed.NonDefault {
		if !slices.Equal(fileVals[flag], flagVals[flag]) {
			ignored = append(ignored, flag+": file "+show(flag, fileVals[flag])+", flag "+show(flag, flagVals[flag]))
		}
	}

	if len(ignored) == 0 {
		return
	}

	log.Warn(ctx, "Proposer config flags ignored, the cluster agreed on different values with "+proposerConfigEditCmd, nil,
		z.Str("flags", strings.Join(ignored, "; ")))
}

// warnUnsignedProposerConfigAfterGloas warns post-gloas that the file is still unsigned.
func warnUnsignedProposerConfigAfterGloas(ctx context.Context, gloasActive func() bool) {
	if !gloasActive() {
		return
	}

	log.Warn(ctx, "Proposer config file is unsigned, agree on it cluster-wide with "+proposerConfigEditCmd, nil)
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
