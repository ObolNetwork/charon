// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
)

type feerecipientListConfig struct {
	feerecipientConfig
}

func newFeeRecipientListCmd(runFunc func(context.Context, feerecipientListConfig) error) *cobra.Command {
	var config feerecipientListConfig

	cmd := &cobra.Command{
		Use:   "list",
		Short: "Display the latest builder registration details for each validator.",
		Long:  "Displays the most recent builder registration for each validator, selecting the entry with the highest timestamp from the cluster lock file, the overrides file, or the remote API.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFunc(cmd.Context(), config)
		},
	}

	cmd.Flags().StringSliceVar(&config.ValidatorPublicKeys, "validator-public-keys", []string{}, "Optional comma-separated list of validator public keys to list builder registrations for.")
	cmd.Flags().StringVar(&config.LockFilePath, lockFilePath.String(), ".charon/cluster-lock.json", "Path to the cluster lock file defining the distributed validator cluster.")
	cmd.Flags().StringVar(&config.OverridesFilePath, "overrides-file", ".charon/builder_registrations_overrides.json", "Path to the builder registrations overrides file.")

	bindFeeRecipientRemoteAPIFlags(cmd, &config.feerecipientConfig)

	return cmd
}

// registrationEntry holds resolved builder registration data for a single validator.
type registrationEntry struct {
	Pubkey       string
	FeeRecipient string
	GasLimit     uint64
	Timestamp    time.Time
	// Sources lists the source names (lock, overrides, remote) whose record
	// is equivalent to this winning entry, in canonical order.
	Sources []string
}

const (
	sourceLock      = "lock"
	sourceOverrides = "overrides"
	sourceRemote    = "remote"
)

// resolveLatestRegistrations returns the latest builder registration for each validator
// by comparing timestamps from the cluster lock, overrides file, and remote API quorum map.
func resolveLatestRegistrations(cl cluster.Lock, overrides, remote map[string]registrationEntry, pubkeyFilter map[string]struct{}) []registrationEntry {
	var entries []registrationEntry

	for _, dv := range cl.Validators {
		pubkeyHex := dv.PublicKeyHex()
		normalized := normalizePubkey(pubkeyHex)

		if len(pubkeyFilter) > 0 {
			if _, ok := pubkeyFilter[normalized]; !ok {
				continue
			}
		}

		lockEntry := registrationEntry{
			FeeRecipient: "0x" + hex.EncodeToString(dv.BuilderRegistration.Message.FeeRecipient),
			GasLimit:     uint64(dv.BuilderRegistration.Message.GasLimit),
			Timestamp:    dv.BuilderRegistration.Message.Timestamp,
		}

		override, hasOverride := overrides[normalized]
		remoteEntry, hasRemote := remote[normalized]

		winner := lockEntry
		if hasOverride && override.Timestamp.After(winner.Timestamp) {
			winner = override
		}

		if hasRemote && remoteEntry.Timestamp.After(winner.Timestamp) {
			winner = remoteEntry
		}

		var sources []string
		if entriesEquivalent(winner, lockEntry) {
			sources = append(sources, sourceLock)
		}

		if hasOverride && entriesEquivalent(winner, override) {
			sources = append(sources, sourceOverrides)
		}

		if hasRemote && entriesEquivalent(winner, remoteEntry) {
			sources = append(sources, sourceRemote)
		}

		entries = append(entries, registrationEntry{
			Pubkey:       pubkeyHex,
			FeeRecipient: winner.FeeRecipient,
			GasLimit:     winner.GasLimit,
			Timestamp:    winner.Timestamp,
			Sources:      sources,
		})
	}

	return entries
}

// entriesEquivalent reports whether two candidate entries represent the same
// record (same fee recipient, gas limit, and timestamp). Pubkey is keyed by
// the caller so is not compared.
func entriesEquivalent(a, b registrationEntry) bool {
	if a.GasLimit != b.GasLimit {
		return false
	}

	if !a.Timestamp.Equal(b.Timestamp) {
		return false
	}

	return strings.EqualFold(a.FeeRecipient, b.FeeRecipient)
}

func runFeeRecipientList(ctx context.Context, config feerecipientListConfig) error {
	cl, err := cluster.LoadClusterLockAndVerify(ctx, config.LockFilePath)
	if err != nil {
		return err
	}

	if len(config.ValidatorPublicKeys) > 0 {
		if err := validatePubkeysInCluster(config.ValidatorPublicKeys, *cl); err != nil {
			return err
		}
	}

	overrides, err := loadOverrides(config.OverridesFilePath, cl.ForkVersion)
	if err != nil {
		return err
	}

	pubkeyFilter := make(map[string]struct{}, len(config.ValidatorPublicKeys))
	for _, pk := range config.ValidatorPublicKeys {
		pubkeyFilter[normalizePubkey(pk)] = struct{}{}
	}

	remote, incomplete, noReg, err := fetchRemoteQuorums(ctx, config, cl.LockHash)
	if err != nil {
		log.Warn(ctx, "Unable to fetch remote builder registrations; showing local data only", err)

		remote, incomplete, noReg = nil, nil, nil
	}

	entries := resolveLatestRegistrations(*cl, overrides, remote, pubkeyFilter)

	if len(entries) == 0 {
		log.Info(ctx, "No builder registrations found", nil)

		return nil
	}

	// Organize output by fee recipient for better readability, using stable sort to maintain original order where fee recipients are the same.
	slices.SortStableFunc(entries, func(a, b registrationEntry) int {
		return strings.Compare(a.FeeRecipient, b.FeeRecipient)
	})

	log.Info(ctx, "Builder registrations", z.Int("total", len(entries)))

	for _, e := range entries {
		log.Info(ctx, "Builder registration for "+e.Pubkey,
			z.Str("fee_recipient", e.FeeRecipient),
			z.U64("gas_limit", e.GasLimit),
			z.I64("timestamp", e.Timestamp.Unix()),
			z.Str("source", strings.Join(e.Sources, "+")),
		)
	}

	if len(incomplete) > 0 {
		log.Info(ctx, "Validators with partial builder registrations on remote", z.Int("total", len(incomplete)))
	}

	if len(noReg) > 0 {
		log.Info(ctx, "Validators unknown to remote API", z.Int("total", len(noReg)))
	}

	remoteOnly := 0

	for _, e := range entries {
		if slices.Contains(e.Sources, sourceRemote) && !slices.Contains(e.Sources, sourceOverrides) {
			remoteOnly++
		}
	}

	if remoteOnly > 0 {
		log.Info(ctx, "Updated registrations are available. "+
			"Use 'charon feerecipient fetch' to save them locally, "+
			"or use 'charon run --fetch-feerecipient-updates' to have Charon check for updates daily.",
			z.Int("total", remoteOnly),
		)
	}

	return nil
}

// fetchRemoteQuorums calls the Obol API and converts the response into a
// pubkey-keyed quorum map plus the incomplete / no-registration pubkey
// lists. Returns an error if the API is unreachable or the response can't
// be processed; callers may choose to treat the error as soft.
func fetchRemoteQuorums(ctx context.Context, config feerecipientListConfig, lockHash []byte) (remote map[string]registrationEntry, incomplete, noReg []string, err error) {
	oAPI, err := obolapi.New(config.PublishAddress, obolapi.WithTimeout(config.PublishTimeout))
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "create Obol API client", z.Str("publish_address", config.PublishAddress))
	}

	resp, err := oAPI.PostFeeRecipientsFetch(ctx, lockHash, config.ValidatorPublicKeys)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "fetch builder registrations from Obol API")
	}

	pv, err := app.ProcessValidators(resp.Validators)
	if err != nil {
		return nil, nil, nil, err
	}

	remote = make(map[string]registrationEntry, len(pv.QuorumMessages))
	for pk, msg := range pv.QuorumMessages {
		if msg == nil {
			continue
		}

		remote[normalizePubkey(pk)] = registrationEntry{
			FeeRecipient: msg.FeeRecipient.String(),
			GasLimit:     msg.GasLimit,
			Timestamp:    msg.Timestamp,
		}
	}

	return remote, pv.Categories.Incomplete, pv.Categories.NoReg, nil
}

// loadOverrides reads the builder registrations overrides file and returns
// a map keyed by normalized validator pubkey hex with the registration details needed for comparison.
func loadOverrides(path string, forkVersion []byte) (map[string]registrationEntry, error) {
	regs, err := app.LoadBuilderRegistrationOverrides(path, eth2p0.Version(forkVersion))
	if err != nil {
		return nil, err
	}

	result := make(map[string]registrationEntry, len(regs))

	for _, reg := range regs {
		if reg == nil || reg.V1 == nil || reg.V1.Message == nil {
			continue
		}

		key := strings.ToLower(hex.EncodeToString(reg.V1.Message.Pubkey[:]))
		result[key] = registrationEntry{
			FeeRecipient: reg.V1.Message.FeeRecipient.String(),
			GasLimit:     reg.V1.Message.GasLimit,
			Timestamp:    reg.V1.Message.Timestamp,
		}
	}

	return result, nil
}
