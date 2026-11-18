// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"slices"
	"strconv"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/core"
)

// proposerConfigEditCmd is the command changing the proposer config cluster-wide.
const proposerConfigEditCmd = "charon alpha edit proposer-config"

// loadProposerConfig loads the validator client proposer config file on start, writing the initial one if it is
// absent and verifying it. Only a file of another
// cluster and an initial config needed but underivable return errors; other failures are logged and a document returned.
func loadProposerConfig(ctx context.Context, conf Config, lock cluster.Lock, nodeIdx cluster.NodeIdx,
	feeRecipientFunc func(core.PubKey) string, gloasActive func() bool,
) (proposerconfig.Document, error) {
	// The initial config is only derived when needed, a valid signed file never depends on it.
	initial := func() (proposerconfig.Document, error) {
		return InitialProposerConfig(lock, conf.ProposerConfigSeed, feeRecipientFunc)
	}

	if conf.TestConfig.Lock != nil {
		// In-memory test lock, there is no cluster directory holding the file.
		return initial()
	}

	path := conf.ProposerConfigFile
	ctx = log.WithCtx(ctx, z.Str("path", path))

	doc, err := proposerconfig.Load(path, lock, nodeIdx)
	if errors.Is(err, proposerconfig.ErrLockHashMismatch) {
		return proposerconfig.Document{}, errors.Wrap(err, "proposer config file belongs to another cluster (after a lock-changing edit, use vc-config/ from its output directory)")
	} else if errors.Is(err, proposerconfig.ErrNotFound) {
		return writeInitialProposerConfig(ctx, path, lock, nodeIdx, initial, gloasActive)
	} else if err != nil {
		// Leave the file untouched for the operator to inspect, charon uses the initial config meanwhile.
		log.Error(ctx, "Failed loading proposer config file, using one derived from the lock and flags; fix it or delete it to regenerate", err)

		doc, err = initial()
		if err != nil {
			return proposerconfig.Document{}, err
		}

		setProposerConfigGauges(doc, false)

		return doc, nil
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

	// Unsigned, the flags seeded it: report where it differs from them.
	if doc.Revision == 0 {
		warnUnsignedProposerConfigDiffers(ctx, lock, doc, initial)
		warnUnsignedProposerConfigAfterGloas(ctx, gloasActive)
	}

	// Signed and verified: report the seeding flags it overrides.
	if doc.Revision > 0 && valid {
		warnSignedProposerConfigOverridesFlags(ctx, doc, conf.ProposerConfigSeed)
	}

	return doc, nil
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
