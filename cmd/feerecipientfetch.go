// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	eth2api "github.com/attestantio/go-eth2-client/api"
	"github.com/spf13/cobra"

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
		Short: "Fetch aggregated builder registrations.",
		Long:  "Fetches aggregated builder registration messages with updated fee recipients from a remote API for validators that have had partial signatures submitted, and writes them to a local JSON file.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFunc(cmd.Context(), config)
		},
	}

	cmd.Flags().StringSliceVar(&config.ValidatorPublicKeys, "validator-public-keys", []string{}, "Optional comma-separated list of validator public keys to fetch builder registrations for.")

	bindFeeRecipientCharonFilesFlags(cmd, &config.feerecipientConfig)
	bindFeeRecipientRemoteAPIFlags(cmd, &config.feerecipientConfig)

	return cmd
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

	// Group validators by status.
	grouped := make(map[obolapi.FeeRecipientStatus][]obolapi.FeeRecipientValidatorStatus)
	for _, vs := range resp.Validators {
		grouped[vs.Status] = append(grouped[vs.Status], vs)
	}

	if vals := grouped[obolapi.FeeRecipientStatusComplete]; len(vals) > 0 {
		log.Info(ctx, "Validators with complete builder registrations", z.Int("count", len(vals)))

		for _, vs := range vals {
			log.Info(ctx, "  Complete registration",
				z.Str("pubkey", vs.Pubkey),
				z.Str("fee_recipient", vs.FeeRecipient),
				z.I64("timestamp_unix", vs.Timestamp.UTC().Unix()),
				z.Str("timestamp", vs.Timestamp.String()))
		}
	}

	if vals := grouped[obolapi.FeeRecipientStatusPartial]; len(vals) > 0 {
		log.Info(ctx, "Validators with partial builder registrations", z.Int("count", len(vals)))

		for _, vs := range vals {
			log.Info(ctx, "  Partial registration",
				z.Str("pubkey", vs.Pubkey),
				z.Str("fee_recipient", vs.FeeRecipient),
				z.I64("timestamp_unix", vs.Timestamp.UTC().Unix()),
				z.Str("timestamp", vs.Timestamp.String()),
				z.Int("partial_count", vs.PartialCount))
		}
	}

	if vals := grouped[obolapi.FeeRecipientStatusUnknown]; len(vals) > 0 {
		log.Info(ctx, "Validators unknown to the API", z.Int("count", len(vals)))

		for _, vs := range vals {
			log.Info(ctx, "  Unknown validator", z.Str("pubkey", vs.Pubkey))
		}
	}

	if len(resp.Registrations) == 0 {
		log.Warn(ctx, "No fully signed builder registrations available yet", nil)

		return nil
	}

	err = writeSignedValidatorRegistrations(config.OverridesFilePath, resp.Registrations)
	if err != nil {
		return errors.Wrap(err, "write builder registrations overrides", z.Str("path", config.OverridesFilePath))
	}

	log.Info(ctx, "Successfully wrote builder registrations overrides",
		z.Int("count", len(resp.Registrations)),
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
