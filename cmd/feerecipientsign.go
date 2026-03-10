// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"time"

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
		Short: "Sign partial builder registration messages.",
		Long:  "Signs new partial builder registration messages with updated fee recipients and publishes them to a remote API.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFunc(cmd.Context(), config)
		},
	}

	bindFeeRecipientCharonFilesFlags(cmd, &config.feerecipientConfig)
	bindFeeRecipientRemoteAPIFlags(cmd, &config.feerecipientConfig)

	cmd.Flags().StringVar(&config.ValidatorKeysDir, validatorKeysDir.String(), ".charon/validator_keys", "Path to the directory containing the validator private key share files and passwords.")
	cmd.Flags().StringSliceVar(&config.ValidatorPublicKeys, "validator-public-keys", nil, "[REQUIRED] Comma-separated list of validator public keys to sign builder registrations for.")
	cmd.Flags().StringVar(&config.FeeRecipient, "fee-recipient", "", "[REQUIRED] New fee recipient address to be applied to all specified validators.")

	wrapPreRunE(cmd, func(cmd *cobra.Command, _ []string) error {
		mustMarkFlagRequired(cmd, "validator-public-keys")
		mustMarkFlagRequired(cmd, "fee-recipient")

		return nil
	})

	return cmd
}

func runFeeRecipientSign(ctx context.Context, config feerecipientSignConfig) error {
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

	// Filter pubkeys based on their current status on the remote API.
	pubkeysToSign, err := filterPubkeysByStatus(ctx, oAPI, cl.LockHash, config.ValidatorPublicKeys, config.FeeRecipient)
	if err != nil {
		return err
	}

	if len(pubkeysToSign) == 0 {
		log.Info(ctx, "No validators require signing")
		return nil
	}

	// Build and sign partial registrations.
	partialRegs, err := buildPartialRegistrations(config.FeeRecipient, time.Now(), pubkeysToSign, *cl, shares)
	if err != nil {
		return err
	}

	for _, reg := range partialRegs {
		log.Info(ctx, "Signed partial builder registration",
			z.Str("validator_pubkey", hex.EncodeToString(reg.Message.Pubkey[:])),
			z.Str("fee_recipient", config.FeeRecipient),
			z.I64("timestamp", reg.Message.Timestamp.Unix()),
		)
	}

	log.Info(ctx, "Submitting partial builder registrations", z.Int("count", len(partialRegs)))

	err = oAPI.PostPartialFeeRecipients(ctx, cl.LockHash, shareIdx, partialRegs)
	if err != nil {
		return errors.Wrap(err, "submit partial builder registrations to Obol API")
	}

	log.Info(ctx, "Successfully submitted partial builder registrations", z.Int("count", len(partialRegs)))

	return nil
}

// filterPubkeysByStatus fetches the current status for each pubkey from the remote API and returns
// only those that need signing. Complete registrations are skipped, partial registrations with
// mismatched fee recipients cause an error, and unknown/partial with matching fee recipients proceed.
func filterPubkeysByStatus(
	ctx context.Context,
	oAPI obolapi.Client,
	lockHash []byte,
	requestedPubkeys []string,
	feeRecipient string,
) ([]eth2p0.BLSPubKey, error) {
	resp, err := oAPI.PostFeeRecipientsFetch(ctx, lockHash, requestedPubkeys)
	if err != nil {
		return nil, errors.Wrap(err, "fetch builder registration status from Obol API")
	}

	statusByPubkey := make(map[string]obolapi.FeeRecipientValidatorStatus)
	for _, vs := range resp.Validators {
		statusByPubkey[strings.ToLower(vs.Pubkey)] = vs
	}

	var pubkeysToSign []eth2p0.BLSPubKey

	for _, valPubKey := range requestedPubkeys {
		normalizedKey := strings.ToLower(valPubKey)
		if !strings.HasPrefix(normalizedKey, "0x") {
			normalizedKey = "0x" + normalizedKey
		}

		vs, ok := statusByPubkey[normalizedKey]

		if ok && vs.Status == obolapi.FeeRecipientStatusComplete {
			log.Info(ctx, "Validator already has a complete builder registration, skipping",
				z.Str("pubkey", valPubKey),
				z.Str("fee_recipient", vs.FeeRecipient))

			continue
		}

		if ok && vs.Status == obolapi.FeeRecipientStatusPartial {
			if !strings.EqualFold(vs.FeeRecipient, feeRecipient) {
				return nil, errors.New("fee recipient mismatch with existing partial registration",
					z.Str("pubkey", valPubKey),
					z.Str("existing_fee_recipient", vs.FeeRecipient),
					z.Str("requested_fee_recipient", feeRecipient),
				)
			}

			log.Info(ctx, "Validator has partial builder registration with matching fee recipient, proceeding",
				z.Str("pubkey", valPubKey),
				z.Str("fee_recipient", vs.FeeRecipient),
				z.Int("partial_count", vs.PartialCount))
		}

		pubkeyBytes, err := hex.DecodeString(strings.TrimPrefix(valPubKey, "0x"))
		if err != nil {
			return nil, errors.Wrap(err, "decode pubkey", z.Str("validator_public_key", valPubKey))
		}

		if len(pubkeyBytes) != len(eth2p0.BLSPubKey{}) {
			return nil, errors.New("invalid pubkey length", z.Int("length", len(pubkeyBytes)), z.Str("validator_public_key", valPubKey))
		}

		pubkeysToSign = append(pubkeysToSign, eth2p0.BLSPubKey(pubkeyBytes))
	}

	return pubkeysToSign, nil
}

// buildPartialRegistrations creates partial builder registration messages for each pubkey,
// signs them with the operator's key share, and returns the signed partial registrations.
func buildPartialRegistrations(
	feeRecipientHex string,
	timestamp time.Time,
	pubkeys []eth2p0.BLSPubKey,
	cl cluster.Lock,
	shares keystore.ValidatorShares,
) ([]obolapi.PartialRegistration, error) {
	feeRecipientBytes, err := hex.DecodeString(strings.TrimPrefix(feeRecipientHex, "0x"))
	if err != nil {
		return nil, errors.Wrap(err, "decode fee recipient address")
	}

	var feeRecipient [20]byte
	copy(feeRecipient[:], feeRecipientBytes)

	partialRegs := make([]obolapi.PartialRegistration, 0, len(pubkeys))

	for _, pubkey := range pubkeys {
		var existingReg *cluster.BuilderRegistration

		for _, dv := range cl.Validators {
			if bytes.Equal(dv.PubKey, pubkey[:]) {
				existingReg = &dv.BuilderRegistration
				break
			}
		}

		if existingReg == nil || existingReg.Message.Timestamp.IsZero() {
			return nil, errors.New("no existing builder registration found for validator", z.Str("pubkey", hex.EncodeToString(pubkey[:])))
		}

		regMsg := &eth2v1.ValidatorRegistration{
			FeeRecipient: feeRecipient,
			GasLimit:     uint64(existingReg.Message.GasLimit),
			Timestamp:    timestamp,
			Pubkey:       pubkey,
		}

		sigRoot, err := registration.GetMessageSigningRoot(regMsg, eth2p0.Version(cl.ForkVersion))
		if err != nil {
			return nil, errors.Wrap(err, "get signing root for registration message")
		}

		corePubkey, err := core.PubKeyFromBytes(pubkey[:])
		if err != nil {
			return nil, errors.Wrap(err, "convert pubkey to core pubkey")
		}

		secretShare, ok := shares[corePubkey]
		if !ok {
			return nil, errors.New("no key share found for validator pubkey", z.Str("pubkey", hex.EncodeToString(pubkey[:])))
		}

		sig, err := tbls.Sign(secretShare.Share, sigRoot[:])
		if err != nil {
			return nil, errors.Wrap(err, "sign registration message")
		}

		partialRegs = append(partialRegs, obolapi.PartialRegistration{
			Message:   regMsg,
			Signature: sig,
		})
	}

	return partialRegs, nil
}
