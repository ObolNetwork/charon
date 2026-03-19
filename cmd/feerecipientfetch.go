// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	eth2api "github.com/attestantio/go-eth2-client/api"
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
	cl, err := cluster.LoadClusterLockAndVerify(ctx, config.LockFilePath)
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

	err = writeSignedValidatorRegistrations(config.OverridesFilePath, pv.AggregatedRegs)
	if err != nil {
		return errors.Wrap(err, "write builder registrations overrides", z.Str("path", config.OverridesFilePath))
	}

	log.Info(ctx, "Successfully wrote builder registrations overrides",
		z.Int("total", len(pv.AggregatedRegs)),
		z.Str("path", config.OverridesFilePath),
	)

	return nil
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
