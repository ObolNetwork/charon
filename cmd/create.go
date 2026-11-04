// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
)

// zeroAddress is not owned by any user, is often associated with token burn & mint/genesis events and used as a generic null address.
// See https://etherscan.io/address/0x0000000000000000000000000000000000000000.
const zeroAddress = "0x0000000000000000000000000000000000000000"

func newCreateCmd(cmds ...*cobra.Command) *cobra.Command {
	root := &cobra.Command{
		Use:   "create",
		Short: "Create artifacts for a distributed validator cluster",
		Long:  "Create artifacts for a distributed validator cluster. These commands can be used to facilitate the creation of a distributed validator cluster between a group of operators by performing a distributed key generation ceremony, or they can be used to create a local cluster for single operator use cases.",
	}

	root.AddCommand(cmds...)

	return root
}

// validateNetworkConfig returns an error if the network configuration is invalid in the given cluster configuration.
func validateNetworkConfig(network string, testnet eth2util.Network) error {
	// Check if custom testnet configuration is provided first (takes precedence over default network).
	if testnet.IsNonZero() {
		// Add testnet config to supported networks.
		eth2util.AddTestNetwork(testnet)

		return nil
	}

	if network != "" {
		if eth2util.ValidNetwork(network) {
			return nil
		}

		return errors.New("invalid network specified", z.Str("network", network))
	}

	return errors.New("missing --network flag or testnet config flags")
}

// isMainOrGnosis returns true if the network is either mainnet or gnosis.
func isMainOrGnosis(network string) bool {
	return network == eth2util.Mainnet.Name || network == eth2util.Gnosis.Name
}

// validateAddresses checks if we have sufficient addresses. It also fills addresses slices if only one is provided.
//
//nolint:revive // Not really confusing here as they are passed as arguments as well.
func validateAddresses(numVals int, feeRecipientAddrs []string, withdrawalAddrs []string) ([]string, []string, error) {
	if len(feeRecipientAddrs) != numVals && len(feeRecipientAddrs) != 1 {
		return nil, nil, errors.New("mismatching --num-validators and --fee-recipient-addresses",
			z.Int("num_validators", numVals), z.Int("addresses", len(feeRecipientAddrs)))
	}

	if len(withdrawalAddrs) != numVals && len(withdrawalAddrs) != 1 {
		return nil, nil, errors.New("mismatching --num-validators and --withdrawal-addresses",
			z.Int("num_validators", numVals), z.Int("addresses", len(withdrawalAddrs)))
	}

	if len(feeRecipientAddrs) == 1 {
		for i := 1; i < numVals; i++ {
			feeRecipientAddrs = append(feeRecipientAddrs, feeRecipientAddrs[0])
		}
	}

	if len(withdrawalAddrs) == 1 {
		for i := 1; i < numVals; i++ {
			withdrawalAddrs = append(withdrawalAddrs, withdrawalAddrs[0])
		}
	}

	return feeRecipientAddrs, withdrawalAddrs, nil
}

// checksumValidatorAddrs validates and checksums both fee recipient and withdrawal addresses.
// A zero fee recipient only warns; a zero withdrawal address on mainnet or gnosis is an error
// if rejectZeroWithdrawal is set, otherwise a warning.
func checksumValidatorAddrs(ctx context.Context, feeRecipientAddrs, withdrawalAddrs []string, network string, rejectZeroWithdrawal bool) (checksummedFeeRecipients []string, checksummedWithdrawals []string, err error) {
	checksummedFeeRecipients, err = checksumAddrs(ctx, feeRecipientAddrs, "fee recipient", network, false)
	if err != nil {
		return nil, nil, err
	}

	checksummedWithdrawals, err = checksumAddrs(ctx, withdrawalAddrs, "withdrawal", network, rejectZeroWithdrawal)
	if err != nil {
		return nil, nil, err
	}

	return checksummedFeeRecipients, checksummedWithdrawals, nil
}

// checksumAddrs validates the provided addresses (see eth2util.ValidateChecksumAddress) of the given kind
// (e.g. "withdrawal" or "fee recipient") and returns their EIP-55 checksummed forms.
// The zero address on mainnet or gnosis is an error if rejectZero is set, otherwise a warning:
// it is legitimate when the generated deposit data is never used, e.g. split existing keys of
// validators that are already active.
func checksumAddrs(ctx context.Context, addrs []string, kind string, network string, rejectZero bool) ([]string, error) {
	resp := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		checksummed, err := eth2util.ValidateChecksumAddress(addr)
		if err != nil {
			return nil, errors.Wrap(err, "invalid "+kind+" address", z.Str("addr", addr))
		}

		if isMainOrGnosis(network) && checksummed == zeroAddress {
			if rejectZero {
				return nil, errors.New("zero "+kind+" address forbidden on this network", z.Str("network", network))
			}

			log.Warn(ctx, "Zero "+kind+" address on "+network+": only continue if the generated deposit data and registrations will never be used", nil, z.Str("network", network))
		}

		resp = append(resp, checksummed)
	}

	return resp, nil
}
