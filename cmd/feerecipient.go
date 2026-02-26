// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/log"
)

type feerecipientConfig struct {
	ValidatorPublicKeys []string
	PrivateKeyPath      string
	LockFilePath        string
	ValidatorKeysDir    string
	PublishAddress      string
	PublishTimeout      time.Duration
	Log                 log.Config
}

func newFeeRecipientCmd(cmds ...*cobra.Command) *cobra.Command {
	root := &cobra.Command{
		Use:   "feerecipient",
		Short: "Sign and fetch updated fee recipient registrations.",
		Long:  "Sign and fetch updated builder registration messages with new fee recipients using a remote API, enabling the modification of fee recipient addresses without cluster restart.",
	}

	root.AddCommand(cmds...)

	return root
}

func bindFeeRecipientFlags(cmd *cobra.Command, config *feerecipientConfig) {
	cmd.Flags().StringSliceVar(&config.ValidatorPublicKeys, "validator-public-keys", []string{}, "Comma-separated list of validator public keys to update (required for the sign subcommand).")
	cmd.Flags().StringVar(&config.PrivateKeyPath, privateKeyPath.String(), ".charon/charon-enr-private-key", "Path to the charon enr private key file.")
	cmd.Flags().StringVar(&config.ValidatorKeysDir, validatorKeysDir.String(), ".charon/validator_keys", "Path to the directory containing the validator private key share files and passwords.")
	cmd.Flags().StringVar(&config.LockFilePath, lockFilePath.String(), ".charon/cluster-lock.json", "Path to the cluster lock file defining the distributed validator cluster.")
	cmd.Flags().StringVar(&config.PublishAddress, publishAddress.String(), "https://api.obol.tech/v1", "The URL of the remote API.")
	cmd.Flags().DurationVar(&config.PublishTimeout, publishTimeout.String(), 5*time.Minute, "Timeout for publishing to the publish-address API.")
}
