// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/registration"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

type feerecipientFetchConfig struct {
	feerecipientConfig

	OutputDir string
}

const defaultBuilderRegistrationsDir = ".charon/builder_registrations"

func newFeeRecipientFetchCmd(runFunc func(context.Context, feerecipientFetchConfig) error) *cobra.Command {
	var config feerecipientFetchConfig

	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch aggregated fee recipient registrations.",
		Long:  "Fetches aggregated builder registration messages with updated fee recipients from a remote API and writes them to the local builder registrations folder.",
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
	cmd.Flags().StringVar(&config.OutputDir, "output-dir", defaultBuilderRegistrationsDir, "Path to the directory where fetched builder registrations will be stored.")
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

	// Determine which validators to fetch.
	var pubkeys []string
	if len(config.ValidatorPublicKeys) > 0 {
		pubkeys = config.ValidatorPublicKeys
	} else {
		// Fetch all validators from cluster lock.
		for _, dv := range cl.Validators {
			pubkeys = append(pubkeys, "0x"+hex.EncodeToString(dv.PubKey))
		}
	}

	// Create output directory.
	err = os.MkdirAll(config.OutputDir, 0o755)
	if err != nil {
		return errors.Wrap(err, "create output directory")
	}

	for _, pubkeyStr := range pubkeys {
		log.Info(ctx, "Fetching fee recipient registration", z.Str("validator_pubkey", pubkeyStr))

		// Get partial registrations from API.
		resp, err := oAPI.GetPartialFeeRecipients(ctx, pubkeyStr, cl.LockHash, cl.Threshold)
		if err != nil {
			if errors.Is(err, obolapi.ErrNoValue) {
				log.Warn(ctx, "No fee recipient registration found for validator", nil, z.Str("validator_pubkey", pubkeyStr))
				continue
			}

			return errors.Wrap(err, "fetch partial fee recipient registrations from Obol API")
		}

		if len(resp.Partials) < cl.Threshold {
			log.Warn(ctx, "Insufficient partial signatures for aggregation",
				nil,
				z.Str("validator_pubkey", pubkeyStr),
				z.Int("partial_count", len(resp.Partials)),
				z.Int("threshold", cl.Threshold))

			continue
		}

		// Aggregate partial signatures.
		signedReg, err := aggregateFeeRecipientRegistration(ctx, *cl, pubkeyStr, resp)
		if err != nil {
			return errors.Wrap(err, "aggregate fee recipient registration")
		}

		// Write to output file.
		filename := filepath.Join(config.OutputDir, strings.TrimPrefix(pubkeyStr, "0x")+".json")

		err = writeSignedValidatorRegistration(filename, signedReg)
		if err != nil {
			return errors.Wrap(err, "write signed validator registration", z.Str("filename", filename))
		}

		log.Info(ctx, "Successfully fetched fee recipient registration",
			z.Str("validator_pubkey", pubkeyStr),
			z.Str("output_file", filename),
		)
	}

	return nil
}

// aggregateFeeRecipientRegistration aggregates partial BLS signatures into a full registration.
func aggregateFeeRecipientRegistration(ctx context.Context, cl cluster.Lock, pubkeyStr string, resp obolapi.PartialFeeRecipientResponse) (*eth2api.VersionedSignedValidatorRegistration, error) {
	if len(resp.Partials) == 0 {
		return nil, errors.New("no partial registrations")
	}

	// Use the message from the first partial (all should have the same message).
	msg := resp.Partials[0].Message

	// Get the validator's group public key for verification.
	pubkeyBytes, err := hex.DecodeString(strings.TrimPrefix(pubkeyStr, "0x"))
	if err != nil {
		return nil, errors.Wrap(err, "decode validator pubkey")
	}

	// Find the validator's public shares in the cluster lock.
	var pubShares []tbls.PublicKey

	for _, dv := range cl.Validators {
		if hex.EncodeToString(dv.PubKey) == strings.TrimPrefix(pubkeyStr, "0x") {
			for _, share := range dv.PubShares {
				pk, err := tblsconv.PubkeyFromBytes(share)
				if err != nil {
					return nil, errors.Wrap(err, "parse public share")
				}

				pubShares = append(pubShares, pk)
			}

			break
		}
	}

	if len(pubShares) == 0 {
		return nil, errors.New("validator not found in cluster lock")
	}

	// Compute signing root for verification.
	sigRoot, err := registration.GetMessageSigningRoot(msg, eth2p0.Version(cl.ForkVersion))
	if err != nil {
		return nil, errors.Wrap(err, "get signing root")
	}

	// Collect partial signatures with their share indices.
	partialSigs := make(map[int]tbls.Signature)

	for _, partial := range resp.Partials {
		sig, err := tblsconv.SignatureFromBytes(partial.Signature)
		if err != nil {
			return nil, errors.Wrap(err, "parse partial signature")
		}

		// Verify partial signature against the corresponding public share.
		if partial.ShareIdx < 1 || partial.ShareIdx > len(pubShares) {
			return nil, errors.New("invalid share index", z.Int("share_idx", partial.ShareIdx))
		}

		err = tbls.Verify(pubShares[partial.ShareIdx-1], sigRoot[:], sig)
		if err != nil {
			log.Warn(ctx, "Invalid partial signature, skipping",
				err,
				z.Int("share_idx", partial.ShareIdx),
			)

			continue
		}

		partialSigs[partial.ShareIdx] = sig
	}

	if len(partialSigs) < cl.Threshold {
		return nil, errors.New("insufficient valid partial signatures",
			z.Int("valid_count", len(partialSigs)),
			z.Int("threshold", cl.Threshold),
		)
	}

	// Aggregate signatures.
	fullSig, err := tbls.ThresholdAggregate(partialSigs)
	if err != nil {
		return nil, errors.Wrap(err, "threshold aggregate signatures")
	}

	// Verify aggregated signature against the group public key.
	groupPubkey, err := tblsconv.PubkeyFromBytes(pubkeyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse group public key")
	}

	err = tbls.Verify(groupPubkey, sigRoot[:], fullSig)
	if err != nil {
		return nil, errors.Wrap(err, "verify aggregated signature")
	}

	// Build the final signed registration.
	return &eth2api.VersionedSignedValidatorRegistration{
		Version: eth2spec.BuilderVersionV1,
		V1: &eth2v1.SignedValidatorRegistration{
			Message:   msg,
			Signature: eth2p0.BLSSignature(fullSig),
		},
	}, nil
}

// writeSignedValidatorRegistration writes the signed registration to a JSON file.
func writeSignedValidatorRegistration(filename string, reg *eth2api.VersionedSignedValidatorRegistration) error {
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return errors.Wrap(err, "marshal registration to JSON")
	}

	err = os.WriteFile(filename, data, 0o644) //nolint:gosec // G306: world-readable output file is intentional
	if err != nil {
		return errors.Wrap(err, "write file")
	}

	return nil
}
