// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
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
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/eth2util/registration"
	"github.com/obolnetwork/charon/tbls"
)

type feerecipientSignConfig struct {
	feerecipientConfig

	FeeRecipient string
}

func newFeeRecipientSignCmd(runFunc func(context.Context, feerecipientSignConfig) error) *cobra.Command {
	var config feerecipientSignConfig

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign partial fee recipient registration messages.",
		Long:  "Signs new partial builder registration messages with updated fee recipients and publishes them to a remote API.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFunc(cmd.Context(), config)
		},
	}

	bindFeeRecipientFlags(cmd, &config.feerecipientConfig)
	bindFeeRecipientSignFlags(cmd, &config)

	wrapPreRunE(cmd, func(cmd *cobra.Command, _ []string) error {
		mustMarkFlagRequired(cmd, "validator-public-keys")
		mustMarkFlagRequired(cmd, "fee-recipient")

		return nil
	})

	return cmd
}

func bindFeeRecipientSignFlags(cmd *cobra.Command, config *feerecipientSignConfig) {
	cmd.Flags().StringVar(&config.FeeRecipient, "fee-recipient", "", "[REQUIRED] New fee recipient address to be applied to all specified validators.")
}

func runFeeRecipientSign(ctx context.Context, config feerecipientSignConfig) error {
	// Validate fee recipient address.
	if _, err := eth2util.ChecksumAddress(config.FeeRecipient); err != nil {
		return errors.Wrap(err, "invalid fee recipient address", z.Str("fee_recipient", config.FeeRecipient))
	}

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

	// Parse requested validator pubkeys.
	pubkeys := make([]eth2p0.BLSPubKey, 0, len(config.ValidatorPublicKeys))
	for _, valPubKey := range config.ValidatorPublicKeys {
		pubkey, err := hex.DecodeString(strings.TrimPrefix(valPubKey, "0x"))
		if err != nil {
			return errors.Wrap(err, "decode pubkey", z.Str("validator_public_key", valPubKey))
		}

		pubkeys = append(pubkeys, eth2p0.BLSPubKey(pubkey))
	}

	// Parse fee recipient address.
	feeRecipientBytes, err := hex.DecodeString(strings.TrimPrefix(config.FeeRecipient, "0x"))
	if err != nil {
		return errors.Wrap(err, "decode fee recipient address")
	}

	var feeRecipient [20]byte
	copy(feeRecipient[:], feeRecipientBytes)

	// Build partial registrations.
	partialRegs := make([]obolapi.PartialRegistration, 0, len(pubkeys))

	for _, pubkey := range pubkeys {
		// Find existing builder registration in cluster lock.
		var existingReg *cluster.BuilderRegistration

		for _, dv := range cl.Validators {
			if bytes.Equal(dv.PubKey, pubkey[:]) {
				existingReg = &dv.BuilderRegistration
				break
			}
		}

		if existingReg == nil || existingReg.Message.Timestamp.IsZero() {
			return errors.New("no existing builder registration found for validator", z.Str("pubkey", hex.EncodeToString(pubkey[:])))
		}

		// Create new registration with updated fee recipient, keeping gas limit and timestamp.
		regMsg := &eth2v1.ValidatorRegistration{
			FeeRecipient: feeRecipient,
			GasLimit:     uint64(existingReg.Message.GasLimit),
			Timestamp:    existingReg.Message.Timestamp,
			Pubkey:       pubkey,
		}

		// Get signing root.
		sigRoot, err := registration.GetMessageSigningRoot(regMsg, eth2p0.Version(cl.ForkVersion))
		if err != nil {
			return errors.Wrap(err, "get signing root for registration message")
		}

		// Get the secret share for this validator.
		corePubkey, err := core.PubKeyFromBytes(pubkey[:])
		if err != nil {
			return errors.Wrap(err, "convert pubkey to core pubkey")
		}

		secretShare, ok := shares[corePubkey]
		if !ok {
			return errors.New("no key share found for validator pubkey", z.Str("pubkey", hex.EncodeToString(pubkey[:])))
		}

		// Sign with threshold BLS.
		sig, err := tbls.Sign(secretShare.Share, sigRoot[:])
		if err != nil {
			return errors.Wrap(err, "sign registration message")
		}

		partialRegs = append(partialRegs, obolapi.PartialRegistration{
			Message:   regMsg,
			Signature: sig,
		})

		log.Info(ctx, "Signed partial fee recipient registration",
			z.Str("validator_pubkey", hex.EncodeToString(pubkey[:])),
			z.Str("fee_recipient", config.FeeRecipient),
		)
	}

	log.Info(ctx, "Submitting partial fee recipient registrations")

	err = oAPI.PostPartialFeeRecipients(ctx, cl.LockHash, shareIdx, partialRegs)
	if err != nil {
		return errors.Wrap(err, "submit partial fee recipient registrations to Obol API")
	}

	log.Info(ctx, "Successfully submitted partial fee recipient registrations",
		z.Int("count", len(partialRegs)),
	)

	return nil
}
