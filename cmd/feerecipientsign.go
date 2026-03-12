// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
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

// pubkeyToSign pairs a validator public key with the timestamp and gas limit to use when signing
// its registration. For validators with no existing partial registration, the timestamp is set to time.Now() by the first operator.
// For validators already having partials, the timestamp and gas limit are adopted from the existing partial registration,
// so all operators sign the same message.
type pubkeyToSign struct {
	Pubkey    eth2p0.BLSPubKey
	Timestamp time.Time
	GasLimit  uint64
}

type feerecipientSignConfig struct {
	feerecipientConfig

	ValidatorKeysDir string
	FeeRecipient     string
	GasLimit         uint64
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

	bindFeeRecipientRemoteAPIFlags(cmd, &config.feerecipientConfig)

	cmd.Flags().StringVar(&config.LockFilePath, lockFilePath.String(), ".charon/cluster-lock.json", "Path to the cluster lock file defining the distributed validator cluster.")
	cmd.Flags().StringVar(&config.OverridesFilePath, "overrides-file", ".charon/builder_registrations_overrides.json", "Path to the builder registrations overrides file.")
	cmd.Flags().StringVar(&config.PrivateKeyPath, privateKeyPath.String(), ".charon/charon-enr-private-key", "Path to the charon enr private key file.")
	cmd.Flags().StringVar(&config.ValidatorKeysDir, validatorKeysDir.String(), ".charon/validator_keys", "Path to the directory containing the validator private key share files and passwords.")
	cmd.Flags().StringSliceVar(&config.ValidatorPublicKeys, "validator-public-keys", nil, "[REQUIRED] Comma-separated list of validator public keys to sign builder registrations for.")
	cmd.Flags().StringVar(&config.FeeRecipient, "fee-recipient", "", "[REQUIRED] New fee recipient address to be applied to all specified validators.")
	cmd.Flags().Uint64Var(&config.GasLimit, "gas-limit", 0, "Optional gas limit override for builder registrations. If not set, the existing gas limit from the cluster lock or overrides file is used.")

	wrapPreRunE(cmd, func(cmd *cobra.Command, _ []string) error {
		mustMarkFlagRequired(cmd, "validator-public-keys")
		mustMarkFlagRequired(cmd, "fee-recipient")

		return nil
	})

	return cmd
}

// normalizePubkey converts a validator public key to lowercase and removes the 0x prefix.
func normalizePubkey(pubkey string) string {
	return strings.ToLower(strings.TrimPrefix(pubkey, "0x"))
}

// parsePubkey decodes a hex-encoded validator public key and validates its length.
func parsePubkey(pubkeyHex string) (eth2p0.BLSPubKey, error) {
	normalizedKey := normalizePubkey(pubkeyHex)

	pubkeyBytes, err := hex.DecodeString(normalizedKey)
	if err != nil {
		return eth2p0.BLSPubKey{}, errors.Wrap(err, "decode pubkey", z.Str("validator_public_key", pubkeyHex))
	}

	if len(pubkeyBytes) != len(eth2p0.BLSPubKey{}) {
		return eth2p0.BLSPubKey{}, errors.New("invalid pubkey length", z.Int("length", len(pubkeyBytes)), z.Str("validator_public_key", pubkeyHex))
	}

	return eth2p0.BLSPubKey(pubkeyBytes), nil
}

// validatePubkeysInCluster verifies that all requested validator public keys exist in the cluster lock.
func validatePubkeysInCluster(pubkeys []string, cl cluster.Lock) error {
	clusterPubkeys := make(map[string]struct{}, len(cl.Validators))
	for _, dv := range cl.Validators {
		clusterPubkeys[strings.ToLower(dv.PublicKeyHex())] = struct{}{}
	}

	for _, valPubKey := range pubkeys {
		normalized := strings.ToLower(valPubKey)
		if !strings.HasPrefix(normalized, "0x") {
			normalized = "0x" + normalized
		}

		if _, ok := clusterPubkeys[normalized]; !ok {
			return errors.New("validator pubkey not found in cluster lock", z.Str("pubkey", valPubKey))
		}
	}

	return nil
}

// buildValidatorLookup creates a map of validators keyed by normalized public key.
func buildValidatorLookup(validators []obolapi.FeeRecipientValidator) map[string]obolapi.FeeRecipientValidator {
	result := make(map[string]obolapi.FeeRecipientValidator, len(validators))
	for _, v := range validators {
		normalizedKey := normalizePubkey(v.Pubkey)
		result[normalizedKey] = v
	}

	return result
}

// findRegistrationGroups finds the quorum and matching incomplete registration groups for a validator.
func findRegistrationGroups(v *obolapi.FeeRecipientValidator, feeRecipient string) (quorum, matchingIncomplete *obolapi.FeeRecipientBuilderRegistration) {
	for i := range v.BuilderRegistrations {
		reg := &v.BuilderRegistrations[i]
		if reg.Quorum && quorum == nil {
			quorum = reg
		} else if !reg.Quorum && matchingIncomplete == nil && strings.EqualFold(reg.Message.FeeRecipient.String(), feeRecipient) {
			matchingIncomplete = reg
		}
	}

	return quorum, matchingIncomplete
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

	if err := validatePubkeysInCluster(config.ValidatorPublicKeys, *cl); err != nil {
		return err
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

	overrides, err := loadOverridesRegistrations(config.OverridesFilePath)
	if err != nil {
		return err
	}

	pubkeysToSign, err := filterPubkeysByStatus(ctx, oAPI, cl.LockHash, config.ValidatorPublicKeys, config.FeeRecipient, config.GasLimit, *cl, overrides, time.Now)
	if err != nil {
		return err
	}

	if len(pubkeysToSign) == 0 {
		log.Info(ctx, "No validators require signing")
		return nil
	}

	partialRegs, err := buildPartialRegistrations(config.FeeRecipient, pubkeysToSign, *cl, shares)
	if err != nil {
		return err
	}

	for _, reg := range partialRegs {
		log.Info(ctx, "Signed partial builder registration",
			z.Str("validator_pubkey", hex.EncodeToString(reg.Message.Pubkey[:])),
			z.Str("fee_recipient", config.FeeRecipient),
			z.U64("gas_limit", reg.Message.GasLimit),
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

// filterPubkeysByStatus fetches the current registration groups for each pubkey from the remote
// API and returns only those that need signing, each paired with the timestamp and gas limit to
// use for signing. Validators with a quorum-complete registration for the requested fee recipient
// are skipped. In-progress (non-quorum) registrations with a mismatched fee recipient cause an error.
// For validators with a matching in-progress registration, the existing timestamp and gas limit are
// adopted so all operators sign the identical message. For unknown validators, now() and the
// gas limit from the config override or cluster lock are used.
func filterPubkeysByStatus(
	ctx context.Context,
	oAPI obolapi.Client,
	lockHash []byte,
	requestedPubkeys []string,
	feeRecipient string,
	gasLimitOverride uint64,
	cl cluster.Lock,
	overrides map[string]eth2v1.ValidatorRegistration,
	now func() time.Time,
) ([]pubkeyToSign, error) {
	resp, err := oAPI.PostFeeRecipientsFetch(ctx, lockHash, requestedPubkeys)
	if err != nil {
		return nil, errors.Wrap(err, "fetch builder registration status from Obol API")
	}

	validatorByPubkey := buildValidatorLookup(resp.Validators)

	var pubkeysToSign []pubkeyToSign

	for _, valPubKey := range requestedPubkeys {
		normalizedKey := normalizePubkey(valPubKey)

		v, ok := validatorByPubkey[normalizedKey]

		// Default: anchor new timestamp and resolve gas limit.
		// These will be overridden if there's a matching incomplete registration.
		timestamp := now()
		gasLimit := resolveGasLimit(gasLimitOverride, cl, overrides, normalizedKey)

		if ok {
			// Find the first incomplete group whose fee recipient matches the requested one.
			// Stale incompletes (different fee recipient) are ignored — they may linger on the
			// API after quorum was reached for a previous fee recipient and must not block new
			// fee recipient changes.
			quorumGroup, matchingIncomplete := findRegistrationGroups(&v, feeRecipient)

			if quorumGroup != nil && strings.EqualFold(quorumGroup.Message.FeeRecipient.String(), feeRecipient) {
				log.Info(ctx, "Validator already has a complete builder registration, skipping",
					z.Str("pubkey", valPubKey),
					z.Str("fee_recipient", quorumGroup.Message.FeeRecipient.String()))

				continue
			}

			if matchingIncomplete != nil {
				// Adopt the timestamp and gas limit from the in-progress group so all operators sign the same message.
				timestamp = matchingIncomplete.Message.Timestamp
				gasLimit = matchingIncomplete.Message.GasLimit

				log.Info(ctx, "Validator has partial builder registration with matching fee recipient, proceeding",
					z.Str("pubkey", valPubKey),
					z.Str("fee_recipient", matchingIncomplete.Message.FeeRecipient.String()),
					z.Int("partial_count", len(matchingIncomplete.PartialSignatures)))
			} else if quorumGroup == nil {
				// Check if there's any incomplete group (with a different fee recipient) and no quorum yet.
				// This means another operator started a fee change that hasn't completed — block.
				for _, reg := range v.BuilderRegistrations {
					if !reg.Quorum {
						return nil, errors.New("fee recipient mismatch with existing partial registration; wait for the in-progress registration to complete or coordinate with your cluster operators",
							z.Str("pubkey", valPubKey),
							z.Str("existing_fee_recipient", reg.Message.FeeRecipient.String()),
							z.Str("requested_fee_recipient", feeRecipient),
						)
					}
				}
				// No in-progress group and no quorum: use defaults set above.
			}
			// else: Quorum exists with different fee, no matching incomplete: use defaults set above.
		}
		// else: Unknown validator: use defaults set above.

		pubkey, err := parsePubkey(valPubKey)
		if err != nil {
			return nil, err
		}

		pubkeysToSign = append(pubkeysToSign, pubkeyToSign{
			Pubkey:    pubkey,
			Timestamp: timestamp,
			GasLimit:  gasLimit,
		})
	}

	return pubkeysToSign, nil
}

// resolveGasLimit returns gasLimitOverride if non-zero. Otherwise it picks the gas limit from
// whichever source (cluster lock or overrides file) has the higher timestamp for the given
// validator pubkey. This ensures the most recent registration's gas limit is used.
func resolveGasLimit(gasLimitOverride uint64, cl cluster.Lock, overrides map[string]eth2v1.ValidatorRegistration, normalizedPubkeyHex string) uint64 {
	if gasLimitOverride != 0 {
		return gasLimitOverride
	}

	var (
		bestGasLimit  uint64
		bestTimestamp time.Time
	)

	for _, dv := range cl.Validators {
		if strings.EqualFold(dv.PublicKeyHex(), "0x"+normalizedPubkeyHex) {
			bestGasLimit = uint64(dv.BuilderRegistration.Message.GasLimit)
			bestTimestamp = dv.BuilderRegistration.Message.Timestamp

			break
		}
	}

	if override, ok := overrides[normalizedPubkeyHex]; ok {
		if override.Timestamp.After(bestTimestamp) {
			bestGasLimit = override.GasLimit
		}
	}

	return bestGasLimit
}

// loadOverridesRegistrations reads the builder registrations overrides file and returns
// a map keyed by normalized (lowercase, no 0x prefix) validator pubkey hex. If the file
// does not exist, an empty map is returned.
func loadOverridesRegistrations(path string) (map[string]eth2v1.ValidatorRegistration, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return make(map[string]eth2v1.ValidatorRegistration), nil
	} else if err != nil {
		return nil, errors.Wrap(err, "read overrides file", z.Str("path", path))
	}

	var regs []*eth2api.VersionedSignedValidatorRegistration
	if err := json.Unmarshal(data, &regs); err != nil {
		return nil, errors.Wrap(err, "unmarshal overrides file", z.Str("path", path))
	}

	result := make(map[string]eth2v1.ValidatorRegistration, len(regs))
	for _, reg := range regs {
		if reg == nil || reg.V1 == nil || reg.V1.Message == nil {
			continue
		}

		key := strings.ToLower(hex.EncodeToString(reg.V1.Message.Pubkey[:]))
		result[key] = *reg.V1.Message
	}

	return result, nil
}

// buildPartialRegistrations creates partial builder registration messages for each pubkey,
// signs them with the operator's key share, and returns the signed partial registrations.
func buildPartialRegistrations(
	feeRecipientHex string,
	pubkeys []pubkeyToSign,
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

	for _, p := range pubkeys {
		regMsg := &eth2v1.ValidatorRegistration{
			FeeRecipient: feeRecipient,
			GasLimit:     p.GasLimit,
			Timestamp:    p.Timestamp,
			Pubkey:       p.Pubkey,
		}

		sigRoot, err := registration.GetMessageSigningRoot(regMsg, eth2p0.Version(cl.ForkVersion))
		if err != nil {
			return nil, errors.Wrap(err, "get signing root for registration message")
		}

		corePubkey, err := core.PubKeyFromBytes(p.Pubkey[:])
		if err != nil {
			return nil, errors.Wrap(err, "convert pubkey to core pubkey")
		}

		secretShare, ok := shares[corePubkey]
		if !ok {
			return nil, errors.New("no key share found for validator pubkey", z.Str("pubkey", hex.EncodeToString(p.Pubkey[:])))
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
