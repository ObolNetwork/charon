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
	OverridesFilePath   string
	PublishAddress      string
	PublishTimeout      time.Duration
	Log                 log.Config
}

func newFeeRecipientCmd(cmds ...*cobra.Command) *cobra.Command {
	root := &cobra.Command{
		Use:   "feerecipient",
		Short: "Sign and fetch updated builder registrations.",
		Long:  "Sign and fetch updated builder registration messages with new fee recipients using a remote API, enabling the modification of fee recipient addresses without cluster restart.",
	}

	root.AddCommand(cmds...)

	return root
}

func bindFeeRecipientRemoteAPIFlags(cmd *cobra.Command, config *feerecipientConfig) {
	cmd.Flags().StringVar(&config.PublishAddress, publishAddress.String(), "https://obol-api-nonprod-dev.dev.obol.tech/v1", "The URL of the remote API.")
	// cmd.Flags().StringVar(&config.PublishAddress, publishAddress.String(), "https://api.obol.tech/v1", "The URL of the remote API.")
	cmd.Flags().DurationVar(&config.PublishTimeout, publishTimeout.String(), 5*time.Minute, "Timeout for accessing the remote API.")
}
