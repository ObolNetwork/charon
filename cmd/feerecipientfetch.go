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

	DataDir string
}

const (
	defaultFeeRecipientDataDir            = ".charon"
	builderRegistrationsOverridesFilename = "builder_registrations_overrides.json"
)

func newFeeRecipientFetchCmd(runFunc func(context.Context, feerecipientFetchConfig) error) *cobra.Command {
	var config feerecipientFetchConfig

	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch aggregated fee recipient registrations.",
		Long:  "Fetches aggregated builder registration messages with updated fee recipients from a remote API for validators that have had partial signatures submitted, and writes them to a local JSON file.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFunc(cmd.Context(), config)
		},
	}

	bindFeeRecipientFlags(cmd, &config.feerecipientConfig)
	bindFeeRecipientFetchFlags(cmd, &config)

	return cmd
}

func bindFeeRecipientFetchFlags(cmd *cobra.Command, config *feerecipientFetchConfig) {
	cmd.Flags().StringVar(&config.DataDir, "data-dir", defaultFeeRecipientDataDir, "The directory where the builder_registrations_overrides.json file will be written.")
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

	resp, err := oAPI.GetFeeRecipients(ctx, cl.LockHash)
	if err != nil {
		return errors.Wrap(err, "fetch fee recipient registrations from Obol API")
	}

	// Display per-validator status.
	for _, vs := range resp.Validators {
		log.Info(ctx, "Validator fee recipient status",
			z.Str("pubkey", vs.Pubkey),
			z.Str("status", vs.Status),
			z.Int("partial_count", vs.PartialCount),
		)
	}

	if len(resp.Registrations) == 0 {
		log.Warn(ctx, "No fully signed fee recipient registrations available yet", nil)
		return nil
	}

	// Ensure data directory exists.
	err = os.MkdirAll(config.DataDir, 0o755)
	if err != nil {
		return errors.Wrap(err, "create data directory")
	}

	outputPath := filepath.Join(config.DataDir, builderRegistrationsOverridesFilename)

	err = writeSignedValidatorRegistrations(outputPath, resp.Registrations)
	if err != nil {
		return errors.Wrap(err, "write builder registrations overrides", z.Str("path", outputPath))
	}

	log.Info(ctx, "Successfully wrote builder registrations overrides",
		z.Int("count", len(resp.Registrations)),
		z.Str("path", outputPath),
	)

	return nil
}

// writeSignedValidatorRegistrations writes all signed registrations to a single JSON file.
func writeSignedValidatorRegistrations(filename string, regs []*eth2api.VersionedSignedValidatorRegistration) error {
	data, err := json.MarshalIndent(regs, "", "  ")
	if err != nil {
		return errors.Wrap(err, "marshal registrations to JSON")
	}

	err = os.WriteFile(filename, data, 0o644) //nolint:gosec // G306: world-readable output file is intentional
	if err != nil {
		return errors.Wrap(err, "write file")
	}

	return nil
}
