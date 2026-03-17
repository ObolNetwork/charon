// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
)

type feerecipientListConfig struct {
	ValidatorPublicKeys []string
	LockFilePath        string
	OverridesFilePath   string
	Log                 log.Config
}

func newFeeRecipientListCmd(runFunc func(context.Context, feerecipientListConfig) error) *cobra.Command {
	var config feerecipientListConfig

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List latest builder registration data per validator.",
		Long:  "Lists the latest builder registration data for each validator, picking the entry with the highest timestamp from the cluster lock or overrides file.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFunc(cmd.Context(), config)
		},
	}

	cmd.Flags().StringSliceVar(&config.ValidatorPublicKeys, "validator-public-keys", []string{}, "Optional comma-separated list of validator public keys to list builder registrations for.")
	cmd.Flags().StringVar(&config.LockFilePath, lockFilePath.String(), ".charon/cluster-lock.json", "Path to the cluster lock file defining the distributed validator cluster.")
	cmd.Flags().StringVar(&config.OverridesFilePath, "overrides-file", ".charon/builder_registrations_overrides.json", "Path to the builder registrations overrides file.")

	return cmd
}

// registrationEntry holds resolved builder registration data for a single validator.
type registrationEntry struct {
	Pubkey       string
	FeeRecipient string
	GasLimit     uint64
	Timestamp    int64
}

// resolveLatestRegistrations returns the latest builder registration for each validator
// by comparing timestamps from the cluster lock and overrides file.
func resolveLatestRegistrations(cl cluster.Lock, overrides map[string]registrationSource, pubkeyFilter map[string]struct{}) []registrationEntry {
	var entries []registrationEntry

	for _, dv := range cl.Validators {
		pubkeyHex := dv.PublicKeyHex()
		normalized := normalizePubkey(pubkeyHex)

		if len(pubkeyFilter) > 0 {
			if _, ok := pubkeyFilter[normalized]; !ok {
				continue
			}
		}

		feeRecipient := "0x" + hex.EncodeToString(dv.BuilderRegistration.Message.FeeRecipient)
		gasLimit := uint64(dv.BuilderRegistration.Message.GasLimit)
		timestamp := dv.BuilderRegistration.Message.Timestamp

		if override, ok := overrides[normalized]; ok {
			if override.Timestamp.After(timestamp) {
				feeRecipient = override.FeeRecipient
				gasLimit = override.GasLimit
				timestamp = override.Timestamp
			}
		}

		entries = append(entries, registrationEntry{
			Pubkey:       pubkeyHex,
			FeeRecipient: feeRecipient,
			GasLimit:     gasLimit,
			Timestamp:    timestamp.Unix(),
		})
	}

	return entries
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

	overrides, err := loadOverridesAsSource(config.OverridesFilePath, cl.ForkVersion)
	if err != nil {
		return err
	}

	pubkeyFilter := make(map[string]struct{}, len(config.ValidatorPublicKeys))
	for _, pk := range config.ValidatorPublicKeys {
		pubkeyFilter[normalizePubkey(pk)] = struct{}{}
	}

	entries := resolveLatestRegistrations(*cl, overrides, pubkeyFilter)

	if len(entries) == 0 {
		log.Info(ctx, "No builder registrations found")
		return nil
	}

	log.Info(ctx, "Builder registrations", z.Int("total", len(entries)))

	for _, e := range entries {
		log.Info(ctx, "Builder registration for "+e.Pubkey,
			z.Str("fee_recipient", e.FeeRecipient),
			z.U64("gas_limit", e.GasLimit),
			z.I64("timestamp", e.Timestamp),
		)
	}

	return nil
}

// registrationSource holds fee recipient data extracted from overrides file.
type registrationSource struct {
	FeeRecipient string
	GasLimit     uint64
	Timestamp    time.Time
}

// loadOverridesAsSource reads the builder registrations overrides file and returns
// a map keyed by normalized validator pubkey hex with the registration details needed for comparison.
func loadOverridesAsSource(path string, forkVersion []byte) (map[string]registrationSource, error) {
	regs, err := app.LoadBuilderRegistrationOverrides(path, eth2p0.Version(forkVersion))
	if err != nil {
		return nil, err
	}

	result := make(map[string]registrationSource, len(regs))

	for _, reg := range regs {
		if reg == nil || reg.V1 == nil || reg.V1.Message == nil {
			continue
		}

		key := strings.ToLower(hex.EncodeToString(reg.V1.Message.Pubkey[:]))
		result[key] = registrationSource{
			FeeRecipient: reg.V1.Message.FeeRecipient.String(),
			GasLimit:     reg.V1.Message.GasLimit,
			Timestamp:    reg.V1.Message.Timestamp,
		}
	}

	return result, nil
}
