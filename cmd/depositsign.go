// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
)

type depositSignConfig struct {
	depositConfig

	WithdrawalAddresses []string
	DepositAmounts      []uint
}

func newDepositSignCmd(runFunc func(context.Context, depositSignConfig) error) *cobra.Command {
	var config depositSignConfig

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a new partial deposit message.",
		Long:  "Signs new partial validator deposit messages using a remote API.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFunc(cmd.Context(), config)
		},
	}

	bindDepositFlags(cmd, &config.depositConfig)
	bindDepositSignFlags(cmd, &config)

	wrapPreRunE(cmd, func(cmd *cobra.Command, _ []string) error {
		mustMarkFlagRequired(cmd, "withdrawal-addresses")
		mustMarkFlagRequired(cmd, "validator-public-keys")

		return nil
	})

	return cmd
}

func bindDepositSignFlags(cmd *cobra.Command, config *depositSignConfig) {
	cmd.Flags().StringSliceVar(&config.WithdrawalAddresses, "withdrawal-addresses", []string{}, "[REQUIRED] Withdrawal addresses for which the new deposits will be signed. Either a single address for all specified validator-public-keys or one address per key should be specified.")
	cmd.Flags().UintSliceVar(&config.DepositAmounts, "deposit-amounts", []uint{32}, "Comma separated list of partial deposit amounts (integers) in ETH.")
}

func runDepositSign(ctx context.Context, config depositSignConfig) error {
	identityKey, err := k1util.Load(config.PrivateKeyPath)
	if err != nil {
		return errors.Wrap(err, "load identity key", z.Str("private_key_path", config.PrivateKeyPath))
	}

	cl, err := cluster.LoadClusterLockAndVerify(ctx, config.LockFilePath)
	if err != nil {
		return err
	}

	oAPI, err := obolapi.New(config.PublishAddress, obolapi.WithTimeout(config.PublishTimeout))
	if err != nil {
		return errors.Wrap(err, "create Obol API client", z.Str("publish_address", config.PublishAddress))
	}

	shareIdx, err := keystore.ShareIdxForCluster(*cl, *identityKey.PubKey())
	if err != nil {
		return errors.Wrap(err, "determine operator index from cluster lock for supplied identity key")
	}

	singleWithdrawalAddresses := len(config.WithdrawalAddresses) == 1

	if !singleWithdrawalAddresses && len(config.WithdrawalAddresses) != len(config.ValidatorPublicKeys) {
		return errors.New("either a single withdrawal address for all keys or one per key must be specified",
			z.Int("withdrawal_addresses", len(config.WithdrawalAddresses)),
			z.Int("validator_public_keys", len(config.ValidatorPublicKeys)))
	}

	rawValKeys, err := keystore.LoadFilesUnordered(config.ValidatorKeysDir)
	if err != nil {
		return errors.Wrap(err, "load keystore, check if path exists", z.Str("validator_keys_dir", config.ValidatorKeysDir))
	}

	valKeys, err := rawValKeys.SequencedKeys()
	if err != nil {
		return errors.Wrap(err, "load keystore")
	}

	shares, err := keystore.KeysharesToValidatorPubkey(*cl, valKeys)
	if err != nil {
		return errors.Wrap(err, "match local validator key shares with their counterparty in cluster lock")
	}

	pubkeys := []eth2p0.BLSPubKey{}

	for _, valPubKey := range config.ValidatorPublicKeys {
		pubkey, err := hex.DecodeString(strings.TrimPrefix(valPubKey, "0x"))
		if err != nil {
			return errors.Wrap(err, "decode pubkey", z.Str("validator_public_key", valPubKey))
		}

		blsPK := eth2p0.BLSPubKey(pubkey)

		pubkeys = append(pubkeys, blsPK)
	}

	withdrawalAddrs := [][]byte{}

	for _, wAddr := range config.WithdrawalAddresses {
		withdrawalAddr, err := hex.DecodeString(strings.TrimPrefix(wAddr, "0x"))
		if err != nil {
			return errors.Wrap(err, "decode withdrawal address", z.Str("withdrawal_address", wAddr))
		}

		withdrawalAddrs = append(withdrawalAddrs, withdrawalAddr)
	}

	depositDatas := []eth2p0.DepositData{}

	network, err := eth2util.ForkVersionToNetwork(cl.ForkVersion)
	if err != nil {
		return err
	}

	for i, pubkey := range pubkeys {
		for _, amount := range config.DepositAmounts {
			if !cl.Compounding && (amount < 1 || amount > 32) {
				return errors.New("deposit amount must be between 1 and 32 ETH", z.U64("amount", uint64(amount)))
			}

			if cl.Compounding && (amount < 1 || amount > 2048) {
				return errors.New("deposit amount must be between 1 and 2048 ETH", z.U64("amount", uint64(amount)))
			}

			depositMsg := eth2p0.DepositMessage{
				PublicKey: pubkey,
				Amount:    eth2p0.Gwei(deposit.OneEthInGwei * amount),
			}
			if singleWithdrawalAddresses {
				depositMsg.WithdrawalCredentials = withdrawalAddrs[0]
			} else {
				depositMsg.WithdrawalCredentials = withdrawalAddrs[i]
			}

			sigRoot, err := deposit.GetMessageSigningRoot(depositMsg, network)
			if err != nil {
				return errors.Wrap(err, "get signing root for deposit message")
			}

			corePubkey, err := core.PubKeyFromBytes(pubkey[:])
			if err != nil {
				return errors.Wrap(err, "convert pubkey to core pubkey", z.Str("pubkey", fmt.Sprintf("%x", pubkey)))
			}

			secretShare, ok := shares[corePubkey]
			if !ok {
				return errors.New("no key share found for validator pubkey", z.Str("pubkey", fmt.Sprintf("%x", pubkey)))
			}

			sig, err := tbls.Sign(secretShare.Share, sigRoot[:])
			if err != nil {
				return errors.Wrap(err, "sign deposit message")
			}

			depositDatas = append(depositDatas, eth2p0.DepositData{
				PublicKey:             depositMsg.PublicKey,
				WithdrawalCredentials: depositMsg.WithdrawalCredentials,
				Amount:                depositMsg.Amount,
				Signature:             eth2p0.BLSSignature(sig),
			})
		}
	}

	log.Info(ctx, "Submitting partial deposit message")

	err = oAPI.PostPartialDeposits(ctx, cl.LockHash, shareIdx, depositDatas)
	if err != nil {
		return errors.Wrap(err, "submit partial deposit data to Obol API")
	}

	return nil
}
