// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

type addValidatorsConfig struct {
	Lockfile          string
	NumVals           int
	WithdrawalAddrs   []string
	FeeRecipientAddrs []string
}

func newAddValidatorsCmd(runFunc func(context.Context, addValidatorsConfig) error) *cobra.Command {
	var config addValidatorsConfig

	cmd := &cobra.Command{
		Use:   "add-validators-solo",
		Short: "Creates and adds new validators to a solo distributed validator cluster",
		Long:  `Creates and adds new validators to a distributed validator cluster. It generates keys for the new validators and also generates a new cluster state file with the legacy_lock and add_validators mutations. It is executed by a solo operator cluster.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.Context(), config)
		},
	}

	bindAddValidatorsFlags(cmd, &config)

	return cmd
}

func bindAddValidatorsFlags(cmd *cobra.Command, config *addValidatorsConfig) {
	cmd.Flags().IntVar(&config.NumVals, "num-validators", 1, "The count of new distributed validators to add in the cluster.")
	cmd.Flags().StringVar(&config.Lockfile, "lock-file", ".charon/cluster-lock.json", "The path to the legacy cluster lock file defining distributed validator cluster.")
	cmd.Flags().StringSliceVar(&config.FeeRecipientAddrs, "fee-recipient-addresses", nil, "Comma separated list of Ethereum addresses of the fee recipient for each new validator. Either provide a single fee recipient address or fee recipient addresses for each validator.")
	cmd.Flags().StringSliceVar(&config.WithdrawalAddrs, "withdrawal-addresses", nil, "Comma separated list of Ethereum addresses to receive the returned stake and accrued rewards for each new validator. Either provide a single withdrawal address or withdrawal addresses for each validator.")
}

func runAddValidatorsSolo(_ context.Context, conf addValidatorsConfig) (err error) {
	// TODO(xenowits): Implement this in next PR, see issue https://github.com/ObolNetwork/charon/issues/1887.
	return validateConf(conf)
}

// validateConf returns an error if the provided validators config fails validation checks.
func validateConf(conf addValidatorsConfig) error {
	if conf.NumVals <= 0 {
		return errors.New("insufficient validator count", z.Int("validators", conf.NumVals))
	}

	if len(conf.FeeRecipientAddrs) == 0 {
		return errors.New("empty fee recipient addresses")
	}

	if len(conf.WithdrawalAddrs) == 0 {
		return errors.New("empty withdrawal addresses")
	}

	if len(conf.FeeRecipientAddrs) != len(conf.WithdrawalAddrs) {
		return errors.New("fee recipient and withdrawal addresses lengths mismatch",
			z.Int("fee_recipients", len(conf.FeeRecipientAddrs)),
			z.Int("withdrawal_addresses", len(conf.WithdrawalAddrs)),
		)
	}

	if conf.NumVals > 1 {
		// There can be a single address for n validators.
		if len(conf.FeeRecipientAddrs) == 1 {
			return nil
		}

		// Or, there can be n addresses for n validators.
		if conf.NumVals != len(conf.FeeRecipientAddrs) {
			return errors.New("count of validators and addresses mismatch", z.Int("num_addresses", len(conf.FeeRecipientAddrs)), z.Int("num_validators", conf.NumVals))
		}

		return nil
	}

	// There can only be a single address for a single validator.
	if len(conf.FeeRecipientAddrs) != 1 {
		return errors.New("count of validators and addresses mismatch", z.Int("num_addresses", len(conf.FeeRecipientAddrs)), z.Int("num_validators", conf.NumVals))
	}

	return nil
}
