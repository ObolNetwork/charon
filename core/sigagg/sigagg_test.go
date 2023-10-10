// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package sigagg_test

import (
	"context"
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
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestSigAgg(t *testing.T) {
	ctx := context.Background()

	const (
		threshold = 3
		peers     = 4
	)

	bmock, err := beaconmock.New()
	require.NoError(t, err)

	t.Run("invalid threshold", func(t *testing.T) {
		_, err := sigagg.New(0, sigagg.NewVerifier(bmock))
		require.ErrorContains(t, err, "invalid threshold")
	})

	t.Run("threshold sigs", func(t *testing.T) {
		agg, err := sigagg.New(threshold, sigagg.NewVerifier(bmock))
		require.NoError(t, err)
		err = agg.Aggregate(ctx, core.Duty{}, map[core.PubKey][]core.ParSignedData{"": nil})
		require.ErrorContains(t, err, "require threshold signatures")
	})

	t.Run("partial sigs", func(t *testing.T) {
		var (
			parsigs []core.ParSignedData
			att     = testutil.RandomAttestation()
		)
		for i := 0; i < peers; i++ {
			parsig := core.NewPartialAttestation(att, 0) // All partial sig with the same shareIdx (0)
			parsigs = append(parsigs, parsig)
		}

		agg, err := sigagg.New(threshold, sigagg.NewVerifier(bmock))
		require.NoError(t, err)
		err = agg.Aggregate(ctx, core.Duty{}, map[core.PubKey][]core.ParSignedData{"": parsigs})
		require.ErrorContains(t, err, "number of partial signatures less than threshold")
	})
}

func TestSigAgg_DutyAttester(t *testing.T) {
	ctx := context.Background()

	const (
		threshold = 3
		peers     = 4
	)

	att := core.NewAttestation(testutil.RandomAttestation())

	msgRoots, err := att.MessageRoots()
	require.NoError(t, err)

	bmock, err := beaconmock.New()
	require.NoError(t, err)

	epoch, err := att.Epoch(ctx, bmock)
	require.NoError(t, err)

	msg, err := signing.GetDataRoot(ctx, bmock, att.DomainNames()[0], epoch, msgRoots[0])
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

	for shareIdx, secret := range secrets {
		sig, err := tbls.Sign(secret, msg[:])
		require.NoError(t, err)

		partialAtt := att.Attestation
		partialAtt.Signature = eth2p0.BLSSignature(sig)
		parsig := core.NewPartialAttestation(&partialAtt, shareIdx)

		psigs[shareIdx] = sig
		parsigs = append(parsigs, parsig)
	}

	// Create expected aggregated signature
	aggSig, err := tbls.ThresholdAggregate(psigs)
	require.NoError(t, err)
	expect := []core.Signature{tblsconv.SigToCore(aggSig)}

	agg, err := sigagg.New(threshold, sigagg.NewVerifier(bmock))
	require.NoError(t, err)

	corePubKey := core.PubKeyFrom48Bytes(pubKey)

	// Assert output
	agg.Subscribe(func(_ context.Context, _ core.Duty, set core.SignedDataSet) error {
		require.Len(t, set, 1)

		require.Equal(t, expect, set[corePubKey].Signatures())
		sig, err := tblsconv.SigFromCore(set[corePubKey].Signatures()[0])
		require.NoError(t, err)

		require.NoError(t, tbls.Verify(pubKey, msg[:], sig))
		require.NoError(t, err)

		return nil
	})

	// Run aggregation
	err = agg.Aggregate(ctx, core.Duty{Type: core.DutyAttester}, toMap(corePubKey, parsigs))
	require.NoError(t, err)
}

func TestSigAgg_DutyRandao(t *testing.T) {
	ctx := context.Background()

	const (
		threshold = 3
		peers     = 4
		epoch     = 123
	)

	bmock, err := beaconmock.New()
	require.NoError(t, err)

	randao := core.NewSignedRandao(epoch, eth2p0.BLSSignature{})
	randaoRoots, err := randao.MessageRoots()
	require.NoError(t, err)

	msg, err := signing.GetDataRoot(ctx, bmock, randao.DomainNames()[0], epoch, randaoRoots[0])
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
		sig, err := tbls.Sign(secret, msg[:])
		require.NoError(t, err)

		eth2Sig := tblsconv.SigToETH2(sig)
		parsig := core.NewPartialSignedRandao(epoch, eth2Sig, idx)

		psigs[idx] = sig
		parsigs = append(parsigs, parsig)
	}

	// Create expected aggregated signature
	aggSig, err := tbls.ThresholdAggregate(psigs)
	require.NoError(t, err)
	expect := []core.Signature{tblsconv.SigToCore(aggSig)}

	agg, err := sigagg.New(threshold, sigagg.NewVerifier(bmock))
	require.NoError(t, err)

	corePubkey := core.PubKeyFrom48Bytes(pubKey)

	// Assert output
	agg.Subscribe(func(_ context.Context, _ core.Duty, set core.SignedDataSet) error {
		require.Equal(t, expect, set[corePubkey].Signatures())
		sig, err := tblsconv.SigFromCore(set[corePubkey].Signatures()[0])
		require.NoError(t, err)

		require.NoError(t, tbls.Verify(pubKey, msg[:], sig))
		require.NoError(t, err)

		return nil
	})

	// Run aggregation
	err = agg.Aggregate(ctx, core.Duty{Type: core.DutyRandao}, toMap(corePubkey, parsigs))
	require.NoError(t, err)
}

func TestSigAgg_DutyExit(t *testing.T) {
	ctx := context.Background()

	const (
		threshold = 3
		peers     = 4
		epoch     = 123
	)

	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Generate private shares
	secretKey, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubKey, err := tbls.SecretToPublicKey(secretKey)
	require.NoError(t, err)

	secrets, err := tbls.ThresholdSplit(secretKey, peers, threshold)
	require.NoError(t, err)

	exitMsg := testutil.RandomExit()
	exitMsg.Message.Epoch = epoch

	volexit := core.NewSignedVoluntaryExit(exitMsg)
	exitRoots, err := volexit.MessageRoots()
	require.NoError(t, err)

	msg, err := signing.GetDataRoot(ctx, bmock, volexit.DomainNames()[0], epoch, exitRoots[0])
	require.NoError(t, err)

	// Create partial signatures (in two formats)
	var (
		parsigs []core.ParSignedData
		psigs   map[int]tbls.Signature
	)

	psigs = make(map[int]tbls.Signature)

	for idx, secret := range secrets {
		// Ignoring domain for this test
		sig, err := tbls.Sign(secret, msg[:])
		require.NoError(t, err)

		eth2Sig := tblsconv.SigToETH2(sig)
		parsig := core.NewPartialSignedVoluntaryExit(&eth2p0.SignedVoluntaryExit{
			Message:   volexit.Message,
			Signature: eth2Sig,
		}, idx)

		psigs[idx] = sig
		parsigs = append(parsigs, parsig)
	}

	aggSig, err := tbls.ThresholdAggregate(psigs)
	require.NoError(t, err)
	expect := []core.Signature{tblsconv.SigToCore(aggSig)}

	agg, err := sigagg.New(threshold, sigagg.NewVerifier(bmock))
	require.NoError(t, err)

	corePubkey := core.PubKeyFrom48Bytes(pubKey)

	// Assert output
	agg.Subscribe(func(_ context.Context, _ core.Duty, set core.SignedDataSet) error {
		require.Equal(t, expect, set[corePubkey].Signatures())
		sig, err := tblsconv.SigFromCore(set[corePubkey].Signatures()[0])
		require.NoError(t, err)

		require.NoError(t, tbls.Verify(pubKey, msg[:], sig))
		require.NoError(t, err)

		return nil
	})

	// Run aggregation
	err = agg.Aggregate(ctx, core.Duty{Type: core.DutyExit}, toMap(corePubkey, parsigs))
	require.NoError(t, err)
}

func TestSigAgg_DutyProposer(t *testing.T) {
	ctx := context.Background()

	const (
		threshold = 3
		peers     = 4
	)

	bmock, err := beaconmock.New()
	require.NoError(t, err)

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
			block, err := core.NewVersionedSignedBeaconBlock(test.block)
			require.NoError(t, err)

			msgRoots, err := block.MessageRoots()
			require.NoError(t, err)
			domainNames := block.DomainNames()

			require.Equal(t, len(msgRoots), len(domainNames))

			epoch, err := block.Epoch(ctx, bmock)
			require.NoError(t, err)

			// Create partial signatures (in two formats)
			var (
				msgsPerPeer  map[int][][32]byte
				parsigs      []core.ParSignedData
				psigsPerPeer map[int][]tbls.Signature
			)

			msgsPerPeer = make(map[int][][32]byte)
			psigsPerPeer = make(map[int][]tbls.Signature)

			for idx, secret := range secrets { // For each charon peer
				var sigs []tbls.Signature // Signatures on data by the peer
				// Sign the message roots
				for i, msgRoot := range msgRoots {
					msg, err := signing.GetDataRoot(ctx, bmock, domainNames[i], epoch, msgRoot)
					require.NoError(t, err)
					msgsPerPeer[idx] = append(msgsPerPeer[idx], msg)

					sig, err := tbls.Sign(secret, msg[:])
					require.NoError(t, err)
					sigs = append(sigs, sig)
				}

				var sigCores []core.Signature
				for _, sig := range sigs {
					sigCores = append(sigCores, tblsconv.SigToCore(sig))
				}

				signed, err := block.SetSignatures(sigCores)
				require.NoError(t, err)

				var coreSigs []tbls.Signature
				for _, sig := range signed.Signatures() {
					coreSig, err := tblsconv.SigFromCore(sig)
					require.NoError(t, err)
					coreSigs = append(coreSigs, coreSig)
				}

				require.Equal(t, sigs, coreSigs)

				psigsPerPeer[idx] = sigs
				parsigs = append(parsigs, core.ParSignedData{
					SignedData: signed,
					ShareIdx:   idx,
				})
			}

			// Check if each peer has the same number of signatures.
			sigLens := make(map[int]struct{})
			var sigLen int
			for _, row := range psigsPerPeer {
				sigLen = len(row)
				sigLens[sigLen] = struct{}{}
			}
			require.NotEqual(t, sigLen, 0)

			// Aggregate partial signatures from each column.
			var aggregatedSigs []core.Signature
			for i := 0; i < sigLen; i++ {
				prsigs := make(map[int]tbls.Signature)
				for shareIdx, parsig := range psigsPerPeer {
					prsigs[shareIdx] = parsig[i]
				}

				sig, err := tbls.ThresholdAggregate(prsigs)
				require.NoError(t, err)

				aggregatedSigs = append(aggregatedSigs, tblsconv.SigToCore(sig))
			}

			// Create expected aggregated signature
			expect := aggregatedSigs

			agg, err := sigagg.New(threshold, sigagg.NewVerifier(bmock))
			require.NoError(t, err)

			corePubkey := core.PubKeyFrom48Bytes(pubKey)

			// Assert output
			agg.Subscribe(func(_ context.Context, _ core.Duty, set core.SignedDataSet) error {
				require.Equal(t, expect, set[corePubkey].Signatures())

				var sigs []tbls.Signature
				for _, sig := range set[corePubkey].Signatures() {
					resp, err := tblsconv.SigFromCore(sig)
					require.NoError(t, err)
					sigs = append(sigs, resp)
				}

				for _, msgs := range msgsPerPeer {
					for i := 0; i < sigLen; i++ { // Verify aggregated signatures column-wise
						err := tbls.Verify(pubKey, msgs[i][:], sigs[i])
						require.NoError(t, err)
					}

					break
				}

				return nil
			})

			// Run aggregation
			err = agg.Aggregate(ctx, core.Duty{Type: core.DutyProposer}, toMap(corePubkey, parsigs))
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

	bmock, err := beaconmock.New()
	require.NoError(t, err)

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
			block, err := core.NewVersionedSignedBlindedBeaconBlock(test.block)
			require.NoError(t, err)

			msgRoots, err := block.MessageRoots()
			require.NoError(t, err)

			epoch, err := block.Epoch(ctx, bmock)
			require.NoError(t, err)

			msg, err := signing.GetDataRoot(ctx, bmock, block.DomainNames()[0], epoch, msgRoots[0])
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
				signed, err := block.SetSignatures([]core.Signature{sigCore})
				require.NoError(t, err)

				coreSig, err := tblsconv.SigFromCore(signed.Signatures()[0])
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
			expect := []core.Signature{tblsconv.SigToCore(aggSig)}

			agg, err := sigagg.New(threshold, sigagg.NewVerifier(bmock))
			require.NoError(t, err)

			corePubkey := core.PubKeyFrom48Bytes(pubKey)

			// Assert output
			agg.Subscribe(func(_ context.Context, _ core.Duty, set core.SignedDataSet) error {
				require.Equal(t, expect, set[corePubkey].Signatures())
				sig, err := tblsconv.SigFromCore(set[corePubkey].Signatures()[0])
				require.NoError(t, err)

				require.NoError(t, tbls.Verify(pubKey, msg[:], sig))
				require.NoError(t, err)

				return nil
			})

			// Run aggregation
			err = agg.Aggregate(ctx, core.Duty{Type: core.DutyBuilderProposer}, toMap(corePubkey, parsigs))
			require.NoError(t, err)
		})
	}
}

func TestSigAgg_DutyBuilderRegistration(t *testing.T) {
	ctx := context.Background()

	const (
		threshold = 3
		peers     = 4
		epoch     = 123
	)

	bmock, err := beaconmock.New()
	require.NoError(t, err)

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
			reg, err := core.NewVersionedSignedValidatorRegistration(test.registration)
			require.NoError(t, err)

			msgRoots, err := reg.MessageRoots()
			require.NoError(t, err)

			msg, err := signing.GetDataRoot(ctx, bmock, reg.DomainNames()[0], epoch, msgRoots[0])
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
				signed, err := block.SetSignatures([]core.Signature{sigCore})
				require.NoError(t, err)

				coreSig, err := tblsconv.SigFromCore(signed.Signatures()[0])
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
			expect := []core.Signature{tblsconv.SigToCore(aggSig)}

			agg, err := sigagg.New(threshold, sigagg.NewVerifier(bmock))
			require.NoError(t, err)

			corePubkey := core.PubKeyFrom48Bytes(pubKey)

			// Assert output
			agg.Subscribe(func(_ context.Context, _ core.Duty, set core.SignedDataSet) error {
				require.Equal(t, expect, set[corePubkey].Signatures())
				sig, err := tblsconv.SigFromCore(set[corePubkey].Signatures()[0])
				require.NoError(t, err)

				require.NoError(t, tbls.Verify(pubKey, msg[:], sig))
				require.NoError(t, err)

				return nil
			})

			// Run aggregation
			err = agg.Aggregate(ctx, core.Duty{Type: core.DutyBuilderRegistration}, toMap(core.PubKeyFrom48Bytes(pubKey), parsigs))
			require.NoError(t, err)
		})
	}
}

func toMap(pubkey core.PubKey, datas []core.ParSignedData) map[core.PubKey][]core.ParSignedData {
	return map[core.PubKey][]core.ParSignedData{pubkey: datas}
}
