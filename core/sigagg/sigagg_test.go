// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package sigagg_test

import (
	"context"
	"os"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/sigagg"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
)

func TestMain(m *testing.M) {
	tbls.SetImplementation(tbls.Herumi{})
	code := m.Run()
	os.Exit(code)
}

func TestSigAgg(t *testing.T) {
	ctx := context.Background()

	const (
		threshold = 3
		peers     = 4
	)

	var (
		parsigs []core.ParSignedData
		att     = testutil.RandomAttestation()
	)
	for i := 0; i < peers; i++ {
		parsig := core.NewPartialAttestation(att, 0) // All partial sig with the same shareIdx (0)
		parsigs = append(parsigs, parsig)
	}

	agg := sigagg.New(threshold)
	err := agg.Aggregate(ctx, core.Duty{}, "", parsigs)
	require.ErrorContains(t, err, "number of partial signatures less than threshold")
}

func TestSigAgg_DutyAttester(t *testing.T) {
	ctx := context.Background()

	const (
		threshold = 3
		peers     = 4
	)

	att := testutil.RandomAttestation()

	// Sign the attestation directly (spec domain not required for test)
	msg, err := att.MarshalSSZ()
	require.NoError(t, err)

	// Generate private shares
	secretKey, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubKey, err := tbls.SecretToPublicKey(secretKey)
	require.NoError(t, err)

	secrets, err := tbls.ThresholdSplit(secretKey, peers, threshold)
	require.NoError(t, err)

	// Create partial signatures (in two formats)
	var (
		parsigs []core.ParSignedData
		psigs   map[int]tbls.Signature
	)

	psigs = make(map[int]tbls.Signature)

	for idx, secret := range secrets {
		sig, err := tbls.Sign(secret, msg)
		require.NoError(t, err)

		att.Signature = tblsconv.SigToETH2(sig)
		parsig := core.NewPartialAttestation(att, idx)

		psigs[idx] = sig
		parsigs = append(parsigs, parsig)
	}

	// Create expected aggregated signature
	aggSig, err := tbls.ThresholdAggregate(psigs)
	require.NoError(t, err)
	expect := tblsconv.SigToCore(aggSig)

	agg := sigagg.New(threshold)

	// Assert output
	agg.Subscribe(func(_ context.Context, _ core.Duty, _ core.PubKey, aggData core.SignedData) error {
		require.Equal(t, expect, aggData.Signature())
		sig, err := tblsconv.SigFromCore(aggData.Signature())
		require.NoError(t, err)

		require.NoError(t, tbls.Verify(pubKey, msg, sig))
		require.NoError(t, err)

		return nil
	})

	// Run aggregation
	err = agg.Aggregate(ctx, core.Duty{Type: core.DutyAttester}, "", parsigs)
	require.NoError(t, err)
}

func TestSigAgg_DutyRandao(t *testing.T) {
	ctx := context.Background()

	const (
		epoch     = 123
		threshold = 3
		peers     = 4
	)

	msg := []byte("RANDAO reveal")

	// Generate private shares
	secretKey, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubKey, err := tbls.SecretToPublicKey(secretKey)
	require.NoError(t, err)

	secrets, err := tbls.ThresholdSplit(secretKey, peers, threshold)
	require.NoError(t, err)

	// Create partial signatures (in two formats)
	var (
		parsigs []core.ParSignedData
		psigs   map[int]tbls.Signature
	)

	psigs = make(map[int]tbls.Signature)

	for idx, secret := range secrets {
		sig, err := tbls.Sign(secret, msg)
		require.NoError(t, err)

		eth2Sig := tblsconv.SigToETH2(sig)
		parsig := core.NewPartialSignedRandao(epoch, eth2Sig, idx)

		psigs[idx] = sig
		parsigs = append(parsigs, parsig)
	}

	// Create expected aggregated signature
	aggSig, err := tbls.ThresholdAggregate(psigs)
	require.NoError(t, err)
	expect := tblsconv.SigToCore(aggSig)

	agg := sigagg.New(threshold)

	// Assert output
	agg.Subscribe(func(_ context.Context, _ core.Duty, _ core.PubKey, aggData core.SignedData) error {
		require.Equal(t, expect, aggData.Signature())
		sig, err := tblsconv.SigFromCore(aggData.Signature())
		require.NoError(t, err)

		require.NoError(t, tbls.Verify(pubKey, msg, sig))
		require.NoError(t, err)

		return nil
	})

	// Run aggregation
	err = agg.Aggregate(ctx, core.Duty{Type: core.DutyRandao}, "", parsigs)
	require.NoError(t, err)
}

func TestSigAgg_DutyExit(t *testing.T) {
	ctx := context.Background()

	const (
		threshold = 3
		peers     = 4
	)

	// Generate private shares
	secretKey, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubKey, err := tbls.SecretToPublicKey(secretKey)
	require.NoError(t, err)

	secrets, err := tbls.ThresholdSplit(secretKey, peers, threshold)
	require.NoError(t, err)

	exit := testutil.RandomExit()
	msg, err := exit.Message.MarshalSSZ()
	require.NoError(t, err)

	// Create partial signatures (in two formats)
	var (
		parsigs []core.ParSignedData
		psigs   map[int]tbls.Signature
	)

	psigs = make(map[int]tbls.Signature)

	for idx, secret := range secrets {
		// Ignoring domain for this test
		sig, err := tbls.Sign(secret, msg)
		require.NoError(t, err)

		eth2Sig := tblsconv.SigToETH2(sig)
		parsig := core.NewPartialSignedVoluntaryExit(&eth2p0.SignedVoluntaryExit{
			Message:   exit.Message,
			Signature: eth2Sig,
		}, idx)

		psigs[idx] = sig
		parsigs = append(parsigs, parsig)
	}

	aggSig, err := tbls.ThresholdAggregate(psigs)
	require.NoError(t, err)
	expect := tblsconv.SigToCore(aggSig)

	agg := sigagg.New(threshold)

	// Assert output
	agg.Subscribe(func(_ context.Context, _ core.Duty, _ core.PubKey, aggData core.SignedData) error {
		require.Equal(t, expect, aggData.Signature())
		sig, err := tblsconv.SigFromCore(aggData.Signature())
		require.NoError(t, err)

		require.NoError(t, tbls.Verify(pubKey, msg, sig))
		require.NoError(t, err)

		return nil
	})

	// Run aggregation
	err = agg.Aggregate(ctx, core.Duty{Type: core.DutyExit}, "", parsigs)
	require.NoError(t, err)
}

func TestSigAgg_DutyProposer(t *testing.T) {
	ctx := context.Background()

	const (
		threshold = 3
		peers     = 4
	)

	// Generate private shares
	secretKey, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubKey, err := tbls.SecretToPublicKey(secretKey)
	require.NoError(t, err)

	secrets, err := tbls.ThresholdSplit(secretKey, peers, threshold)
	require.NoError(t, err)

	tests := []struct {
		name  string
		block *eth2spec.VersionedSignedBeaconBlock
	}{
		{
			name: "phase0 block",
			block: &eth2spec.VersionedSignedBeaconBlock{
				Version: eth2spec.DataVersionPhase0,
				Phase0: &eth2p0.SignedBeaconBlock{
					Message:   testutil.RandomPhase0BeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
			},
		},
		{
			name: "altair block",
			block: &eth2spec.VersionedSignedBeaconBlock{
				Version: eth2spec.DataVersionAltair,
				Altair: &altair.SignedBeaconBlock{
					Message:   testutil.RandomAltairBeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
			},
		},
		{
			name: "bellatrix block",
			block: &eth2spec.VersionedSignedBeaconBlock{
				Version: eth2spec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBeaconBlock{
					Message:   testutil.RandomBellatrixBeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
			},
		},
		{
			name: "capella block",
			block: &eth2spec.VersionedSignedBeaconBlock{
				Version: eth2spec.DataVersionCapella,
				Capella: &capella.SignedBeaconBlock{
					Message:   testutil.RandomCapellaBeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Ignoring Domain for this test
			msg, err := test.block.Root()
			require.NoError(t, err)

			// Create partial signatures (in two formats)
			var (
				parsigs []core.ParSignedData
				psigs   map[int]tbls.Signature
			)

			psigs = make(map[int]tbls.Signature)

			for idx, secret := range secrets {
				sig, err := tbls.Sign(secret, msg[:])
				require.NoError(t, err)

				block, err := core.NewVersionedSignedBeaconBlock(test.block)
				require.NoError(t, err)

				sigCore := tblsconv.SigToCore(sig)
				signed, err := block.SetSignature(sigCore)
				require.NoError(t, err)

				coreSig, err := tblsconv.SigFromCore(signed.Signature())
				require.NoError(t, err)

				require.Equal(t, sig, coreSig)

				psigs[idx] = sig
				parsigs = append(parsigs, core.ParSignedData{
					SignedData: signed,
					ShareIdx:   idx,
				})
			}

			// Create expected aggregated signature
			aggSig, err := tbls.ThresholdAggregate(psigs)
			require.NoError(t, err)
			expect := tblsconv.SigToCore(aggSig)

			agg := sigagg.New(threshold)

			// Assert output
			agg.Subscribe(func(_ context.Context, _ core.Duty, _ core.PubKey, aggData core.SignedData) error {
				require.Equal(t, expect, aggData.Signature())
				sig, err := tblsconv.SigFromCore(aggData.Signature())
				require.NoError(t, err)

				require.NoError(t, tbls.Verify(pubKey, msg[:], sig))
				require.NoError(t, err)

				return nil
			})

			// Run aggregation
			err = agg.Aggregate(ctx, core.Duty{Type: core.DutyProposer}, "", parsigs)
			require.NoError(t, err)
		})
	}
}

func TestSigAgg_DutyBuilderProposer(t *testing.T) {
	ctx := context.Background()

	const (
		threshold = 3
		peers     = 4
	)

	// Generate private shares
	secretKey, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubKey, err := tbls.SecretToPublicKey(secretKey)
	require.NoError(t, err)

	secrets, err := tbls.ThresholdSplit(secretKey, peers, threshold)
	require.NoError(t, err)

	tests := []struct {
		name  string
		block *eth2api.VersionedSignedBlindedBeaconBlock
	}{
		{
			name: "bellatrix block",
			block: &eth2api.VersionedSignedBlindedBeaconBlock{
				Version: eth2spec.DataVersionBellatrix,
				Bellatrix: &eth2bellatrix.SignedBlindedBeaconBlock{
					Message:   testutil.RandomBellatrixBlindedBeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
			},
		},
		{
			name: "capella block",
			block: &eth2api.VersionedSignedBlindedBeaconBlock{
				Version: eth2spec.DataVersionCapella,
				Capella: &eth2capella.SignedBlindedBeaconBlock{
					Message:   testutil.RandomCapellaBlindedBeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Ignoring Domain for this test
			msg, err := test.block.Root()
			require.NoError(t, err)

			// Create partial signatures (in two formats)
			var (
				parsigs []core.ParSignedData
				psigs   map[int]tbls.Signature
			)

			psigs = make(map[int]tbls.Signature)

			for idx, secret := range secrets {
				sig, err := tbls.Sign(secret, msg[:])
				require.NoError(t, err)

				block, err := core.NewVersionedSignedBlindedBeaconBlock(test.block)
				require.NoError(t, err)

				sigCore := tblsconv.SigToCore(sig)
				signed, err := block.SetSignature(sigCore)
				require.NoError(t, err)

				coreSig, err := tblsconv.SigFromCore(signed.Signature())
				require.NoError(t, err)

				require.Equal(t, sig, coreSig)

				psigs[idx] = sig
				parsigs = append(parsigs, core.ParSignedData{
					SignedData: signed,
					ShareIdx:   idx,
				})
			}

			// Create expected aggregated signature
			aggSig, err := tbls.ThresholdAggregate(psigs)
			require.NoError(t, err)
			expect := tblsconv.SigToCore(aggSig)

			agg := sigagg.New(threshold)

			// Assert output
			agg.Subscribe(func(_ context.Context, _ core.Duty, _ core.PubKey, aggData core.SignedData) error {
				require.Equal(t, expect, aggData.Signature())
				sig, err := tblsconv.SigFromCore(aggData.Signature())
				require.NoError(t, err)

				require.NoError(t, tbls.Verify(pubKey, msg[:], sig))
				require.NoError(t, err)

				return nil
			})

			// Run aggregation
			err = agg.Aggregate(ctx, core.Duty{Type: core.DutyBuilderProposer}, "", parsigs)
			require.NoError(t, err)
		})
	}
}

func TestSigAgg_DutyBuilderRegistration(t *testing.T) {
	ctx := context.Background()

	const (
		threshold = 3
		peers     = 4
	)

	// Generate private shares
	secretKey, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubKey, err := tbls.SecretToPublicKey(secretKey)
	require.NoError(t, err)

	secrets, err := tbls.ThresholdSplit(secretKey, peers, threshold)
	require.NoError(t, err)

	tests := []struct {
		name         string
		registration *eth2api.VersionedSignedValidatorRegistration
	}{
		{
			name: "V1 registration",
			registration: &eth2api.VersionedSignedValidatorRegistration{
				Version: eth2spec.BuilderVersionV1,
				V1: &eth2v1.SignedValidatorRegistration{
					Message:   testutil.RandomValidatorRegistration(t),
					Signature: testutil.RandomEth2Signature(),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Ignoring Domain for this test
			msg, err := test.registration.Root()
			require.NoError(t, err)

			// Create partial signatures (in two formats)
			var (
				parsigs []core.ParSignedData
				psigs   map[int]tbls.Signature
			)

			psigs = make(map[int]tbls.Signature)

			for idx, secret := range secrets {
				sig, err := tbls.Sign(secret, msg[:])
				require.NoError(t, err)

				block, err := core.NewVersionedSignedValidatorRegistration(test.registration)
				require.NoError(t, err)

				sigCore := tblsconv.SigToCore(sig)
				signed, err := block.SetSignature(sigCore)
				require.NoError(t, err)

				coreSig, err := tblsconv.SigFromCore(signed.Signature())
				require.NoError(t, err)

				require.Equal(t, sig, coreSig)

				psigs[idx] = sig
				parsigs = append(parsigs, core.ParSignedData{
					SignedData: signed,
					ShareIdx:   idx,
				})
			}

			// Create expected aggregated signature
			aggSig, err := tbls.ThresholdAggregate(psigs)
			require.NoError(t, err)
			expect := tblsconv.SigToCore(aggSig)

			agg := sigagg.New(threshold)

			// Assert output
			agg.Subscribe(func(_ context.Context, _ core.Duty, _ core.PubKey, aggData core.SignedData) error {
				require.Equal(t, expect, aggData.Signature())
				sig, err := tblsconv.SigFromCore(aggData.Signature())
				require.NoError(t, err)

				require.NoError(t, tbls.Verify(pubKey, msg[:], sig))
				require.NoError(t, err)

				return nil
			})

			// Run aggregation
			err = agg.Aggregate(ctx, core.Duty{Type: core.DutyBuilderRegistration}, "", parsigs)
			require.NoError(t, err)
		})
	}
}
