// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

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
	"github.com/obolnetwork/charon/tbls"
)

type feerecipientFetchConfig struct {
	feerecipientConfig
}

func newFeeRecipientFetchCmd(runFunc func(context.Context, feerecipientFetchConfig) error) *cobra.Command {
	var config feerecipientFetchConfig

	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch aggregated builder registrations.",
		Long:  "Fetches builder registration messages from a remote API and aggregates those with quorum, writing fully signed registrations to a local JSON file.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFunc(cmd.Context(), config)
		},
	}

	cmd.Flags().StringSliceVar(&config.ValidatorPublicKeys, "validator-public-keys", []string{}, "Optional comma-separated list of validator public keys to fetch builder registrations for.")
	cmd.Flags().StringVar(&config.LockFilePath, lockFilePath.String(), ".charon/cluster-lock.json", "Path to the cluster lock file defining the distributed validator cluster.")
	cmd.Flags().StringVar(&config.OverridesFilePath, "overrides-file", ".charon/builder_registrations_overrides.json", "Path to the builder registrations overrides file.")

	bindFeeRecipientRemoteAPIFlags(cmd, &config.feerecipientConfig)

	return cmd
}

// validatorCategories holds categorized validator public keys by registration status.
type validatorCategories struct {
	Complete   []string
	Incomplete []string
	NoReg      []string
}

// aggregatePartialSignatures converts partial signatures into a full aggregated signature.
func aggregatePartialSignatures(partialSigs []obolapi.FeeRecipientPartialSig, pubkey string) (eth2p0.BLSSignature, error) {
	sigsMap := make(map[int]tbls.Signature)

	for _, ps := range partialSigs {
		sigsMap[ps.ShareIndex] = ps.Signature
	}

	fullSig, err := tbls.ThresholdAggregate(sigsMap)
	if err != nil {
		return eth2p0.BLSSignature{}, errors.Wrap(err, "aggregate partial signatures", z.Str("pubkey", pubkey))
	}

	return eth2p0.BLSSignature(fullSig), nil
}

// processValidators aggregates signatures for validators with quorum and categorizes all validators by status.
func processValidators(validators []obolapi.FeeRecipientValidator) ([]*eth2api.VersionedSignedValidatorRegistration, validatorCategories, map[string]int, error) {
	var (
		aggregatedRegs []*eth2api.VersionedSignedValidatorRegistration
		cats           validatorCategories
		// maxPartialSigs tracks the highest partial signature count across
		// all incomplete registrations for a given validator pubkey.
		maxPartialSigs = make(map[string]int)
	)

	for _, val := range validators {
		var hasQuorum, hasIncomplete bool

		for _, reg := range val.BuilderRegistrations {
			if reg.Quorum {
				hasQuorum = true

				fullSig, err := aggregatePartialSignatures(reg.PartialSignatures, val.Pubkey)
				if err != nil {
					return nil, validatorCategories{}, nil, err
				}

				aggregatedRegs = append(aggregatedRegs, &eth2api.VersionedSignedValidatorRegistration{
					Version: eth2spec.BuilderVersionV1,
					V1: &eth2v1.SignedValidatorRegistration{
						Message:   reg.Message,
						Signature: fullSig,
					},
				})
			} else {
				hasIncomplete = true

				if n := len(reg.PartialSignatures); n > maxPartialSigs[val.Pubkey] {
					maxPartialSigs[val.Pubkey] = n
				}
			}
		}

		switch {
		case hasQuorum:
			cats.Complete = append(cats.Complete, val.Pubkey)
		case hasIncomplete:
			cats.Incomplete = append(cats.Incomplete, val.Pubkey)
		default:
			cats.NoReg = append(cats.NoReg, val.Pubkey)
		}
	}

	return aggregatedRegs, cats, maxPartialSigs, nil
}

// logValidatorStatus logs categorized validators with their current registration status.
func logValidatorStatus(ctx context.Context, cats validatorCategories, maxPartialSigs map[string]int) {
	if len(cats.Complete) > 0 {
		log.Info(ctx, "Validators with complete builder registrations", z.Int("count", len(cats.Complete)))

		for _, pubkey := range cats.Complete {
			log.Info(ctx, "  Complete", z.Str("pubkey", pubkey))
		}
	}

	if len(cats.Incomplete) > 0 {
		log.Info(ctx, "Validators with partial builder registrations", z.Int("count", len(cats.Incomplete)))

		for _, pubkey := range cats.Incomplete {
			log.Info(ctx, "  Incomplete", z.Str("pubkey", pubkey), z.Int("partial_signatures", maxPartialSigs[pubkey]))
		}
	}

	if len(cats.NoReg) > 0 {
		log.Info(ctx, "Validators unknown to the API", z.Int("count", len(cats.NoReg)))

		for _, pubkey := range cats.NoReg {
			log.Info(ctx, "  No registrations", z.Str("pubkey", pubkey))
		}
	}
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

	resp, err := oAPI.PostFeeRecipientsFetch(ctx, cl.LockHash, config.ValidatorPublicKeys)
	if err != nil {
		return errors.Wrap(err, "fetch builder registrations from Obol API")
	}

	aggregatedRegs, cats, maxPartialSigs, err := processValidators(resp.Validators)
	if err != nil {
		return err
	}

	logValidatorStatus(ctx, cats, maxPartialSigs)

	if len(aggregatedRegs) == 0 {
		log.Info(ctx, "No fully signed builder registrations available yet")

		return nil
	}

	err = writeSignedValidatorRegistrations(config.OverridesFilePath, aggregatedRegs)
	if err != nil {
		return errors.Wrap(err, "write builder registrations overrides", z.Str("path", config.OverridesFilePath))
	}

	log.Info(ctx, "Successfully wrote builder registrations overrides",
		z.Int("count", len(aggregatedRegs)),
		z.Str("path", config.OverridesFilePath),
	)

	return nil
}

func writeSignedValidatorRegistrations(filename string, regs []*eth2api.VersionedSignedValidatorRegistration) error {
	data, err := json.MarshalIndent(regs, "", "  ")
	if err != nil {
		return errors.Wrap(err, "marshal registrations to JSON")
	}

	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		return errors.Wrap(err, "create output directory")
	}

	err = os.WriteFile(filename, data, 0o644) //nolint:gosec // G306: world-readable output file is intentional
	if err != nil {
		return errors.Wrap(err, "write registrations overrides file")
	}

	return nil
}
