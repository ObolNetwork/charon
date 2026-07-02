// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
)

type feerecipientFetchConfig struct {
	feerecipientConfig
}

func newFeeRecipientFetchCmd(runFunc func(context.Context, feerecipientFetchConfig) error) *cobra.Command {
	var config feerecipientFetchConfig

	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch new fee recipients (builder registrations).",
		Long:  "Fetches builder registration messages from a remote API and aggregates those with quorum, writing them to a local JSON file.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFunc(cmd.Context(), config)
		},
	}

	cmd.Flags().StringSliceVar(&config.ValidatorPublicKeys, "validator-public-keys", []string{}, "Optional comma-separated list of validator public keys to fetch builder registrations for.")
	cmd.Flags().StringVar(&config.LockFilePath, lockFilePath.String(), ".charon/cluster-lock.json", "Path to the cluster lock file defining the distributed validator cluster.")
	cmd.Flags().StringVar(&config.OverridesFilePath, "overrides-file", ".charon/builder_registrations_overrides.json", "Path to the builder registrations overrides file.")

	bindFeeRecipientRemoteAPIFlags(cmd, &config.feerecipientConfig)

	return cmd
}

// logValidatorStatus logs categorized validators with their current registration status.
func logValidatorStatus(ctx context.Context, pv app.ProcessedValidators) {
	cats := pv.Categories

	if len(cats.Complete) > 0 {
		log.Info(ctx, "Validators with complete builder registrations", z.Int("total", len(cats.Complete)))

		for _, pubkey := range cats.Complete {
			if msg := pv.QuorumMessages[pubkey]; msg != nil {
				log.Info(ctx, "  Complete",
					z.Str("pubkey", pubkey),
					z.Str("fee_recipient", msg.FeeRecipient.String()),
					z.U64("gas_limit", msg.GasLimit),
					z.I64("timestamp", msg.Timestamp.Unix()),
				)
			} else {
				log.Info(ctx, "  Complete", z.Str("pubkey", pubkey))
			}
		}
	}

	if len(cats.Incomplete) > 0 {
		log.Info(ctx, "Validators with partial builder registrations", z.Int("total", len(cats.Incomplete)))

		for _, pubkey := range cats.Incomplete {
			indices := pv.PartialSigIndices[pubkey]
			fields := []z.Field{
				z.Str("pubkey", pubkey),
				z.Int("partial_signatures", len(indices)),
				z.Any("submitted_indices", indices),
			}

			if msg := pv.IncompleteMessages[pubkey]; msg != nil {
				fields = append(fields,
					z.Str("fee_recipient", msg.FeeRecipient.String()),
					z.U64("gas_limit", msg.GasLimit),
					z.I64("timestamp", msg.Timestamp.Unix()),
				)
			}

			log.Info(ctx, "  Incomplete", fields...)
		}
	}

	if len(cats.NoReg) > 0 {
		log.Info(ctx, "Validators unknown to the API", z.Int("total", len(cats.NoReg)))

		for _, pubkey := range cats.NoReg {
			log.Info(ctx, "  No registrations", z.Str("pubkey", pubkey))
		}
	}
}

func runFeeRecipientFetch(ctx context.Context, config feerecipientFetchConfig) error {
	cl, err := cluster.LoadClusterLockAndVerify(ctx, config.LockFilePath, config.ExecutionEngineAddr)
	if err != nil {
		return err
	}

	oAPI, err := obolapi.New(config.PublishAddress, obolapi.WithTimeout(config.PublishTimeout))
	if err != nil {
		return errors.Wrap(err, "create Obol API client", z.Str("publish_address", config.PublishAddress))
	}

	resp, err := oAPI.PostFeeRecipientsFetch(ctx, cl.LockHash, config.ValidatorPublicKeys)
	if err != nil {
		return errors.Wrap(err, "fetch builder registrations from Obol API")
	}

	pv, err := app.ProcessValidators(resp.Validators)
	if err != nil {
		return err
	}

	logValidatorStatus(ctx, pv)

	if len(pv.AggregatedRegs) == 0 {
		log.Info(ctx, "No fully signed builder registrations available yet")

		return nil
	}

	mergedRegs, err := mergeFetchedValidatorRegistrations(ctx, config.OverridesFilePath, cl.ForkVersion, pv.AggregatedRegs)
	if err != nil {
		return errors.Wrap(err, "merge builder registrations overrides", z.Str("path", config.OverridesFilePath))
	}

	err = writeSignedValidatorRegistrations(config.OverridesFilePath, mergedRegs)
	if err != nil {
		return errors.Wrap(err, "write builder registrations overrides", z.Str("path", config.OverridesFilePath))
	}

	log.Info(ctx, "Successfully wrote builder registrations overrides",
		z.Int("total", len(mergedRegs)),
		z.Int("fetched", len(pv.AggregatedRegs)),
		z.Str("path", config.OverridesFilePath),
	)

	return nil
}

func mergeFetchedValidatorRegistrations(
	ctx context.Context,
	path string,
	forkVersion []byte,
	fetched []*eth2api.VersionedSignedValidatorRegistration,
) ([]*eth2api.VersionedSignedValidatorRegistration, error) {
	eth2ForkVersion := eth2p0.Version(forkVersion)

	existing, err := app.LoadBuilderRegistrationOverrides(path, eth2ForkVersion)
	if err != nil {
		return nil, err
	}

	verified := fetched
	if eth2ForkVersion != (eth2p0.Version{}) {
		verified = make([]*eth2api.VersionedSignedValidatorRegistration, 0, len(fetched))

		for _, reg := range fetched {
			if err := app.VerifyBuilderRegistrationSignature(reg, eth2ForkVersion); err != nil {
				log.Warn(ctx, "Skipping fetched builder registration with invalid signature", err)
				continue
			}

			verified = append(verified, reg)
		}
	}

	byPubkey := make(map[string]*eth2api.VersionedSignedValidatorRegistration, len(existing)+len(verified))

	add := func(reg *eth2api.VersionedSignedValidatorRegistration) {
		if reg == nil || reg.V1 == nil || reg.V1.Message == nil {
			return
		}

		key := strings.ToLower(hex.EncodeToString(reg.V1.Message.Pubkey[:]))

		prev, ok := byPubkey[key]
		if !ok || reg.V1.Message.Timestamp.After(prev.V1.Message.Timestamp) {
			byPubkey[key] = reg
		}
	}

	for _, reg := range existing {
		add(reg)
	}

	for _, reg := range verified {
		add(reg)
	}

	merged := make([]*eth2api.VersionedSignedValidatorRegistration, 0, len(byPubkey))
	for _, reg := range byPubkey {
		merged = append(merged, reg)
	}

	slices.SortFunc(merged, func(a, b *eth2api.VersionedSignedValidatorRegistration) int {
		aValid := a != nil && a.V1 != nil && a.V1.Message != nil
		bValid := b != nil && b.V1 != nil && b.V1.Message != nil

		if !aValid || !bValid {
			switch {
			case aValid:
				return -1
			case bValid:
				return 1
			default:
				return 0
			}
		}

		return strings.Compare(
			hex.EncodeToString(a.V1.Message.Pubkey[:]),
			hex.EncodeToString(b.V1.Message.Pubkey[:]),
		)
	})

	return merged, nil
}

func writeSignedValidatorRegistrations(filename string, regs []*eth2api.VersionedSignedValidatorRegistration) error {
	data, err := json.MarshalIndent(regs, "", "  ")
	if err != nil {
		return errors.Wrap(err, "marshal registrations to JSON")
	}

	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		return errors.Wrap(err, "create output directory")
	}

	err = os.WriteFile(filename, data, 0o644) //nolint:gosec // G306: world-readable output file is intentional
	if err != nil {
		return errors.Wrap(err, "write registrations overrides file")
	}

	return nil
}
