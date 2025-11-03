// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/log"
)

type depositConfig struct {
	ValidatorPublicKeys []string
	PrivateKeyPath      string
	LockFilePath        string
	ValidatorKeysDir    string
	PublishAddress      string
	PublishTimeout      time.Duration
	Log                 log.Config
}

func newDepositCmd(cmds ...*cobra.Command) *cobra.Command {
	root := &cobra.Command{
		Use:   "deposit",
		Short: "Sign and fetch a new partial deposit.",
		Long:  "Sign and fetch new deposit messages for unactivated validators using a remote API, enabling the modification of a withdrawal address after creation but before activation.",
	}

	root.AddCommand(cmds...)

	return root
}

func bindDepositFlags(cmd *cobra.Command, config *depositConfig) {
	cmd.Flags().StringSliceVar(&config.ValidatorPublicKeys, "validator-public-keys", []string{}, "[REQUIRED] List of validator public keys for which new deposits will be signed.")
	cmd.Flags().StringVar(&config.PrivateKeyPath, privateKeyPath.String(), ".charon/charon-enr-private-key", "Path to the charon enr private key file.")
	cmd.Flags().StringVar(&config.ValidatorKeysDir, validatorKeysDir.String(), ".charon/validator_keys", "Path to the directory containing the validator private key share files and passwords.")
	cmd.Flags().StringVar(&config.LockFilePath, lockFilePath.String(), ".charon/cluster-lock.json", "Path to the cluster lock file defining the distributed validator cluster.")
	cmd.Flags().StringVar(&config.PublishAddress, publishAddress.String(), "https://api.obol.tech/v1", "The URL of the remote API.")
	cmd.Flags().DurationVar(&config.PublishTimeout, publishTimeout.String(), 5*time.Minute, "Timeout for publishing a signed deposit to the publish-address API.")
}
