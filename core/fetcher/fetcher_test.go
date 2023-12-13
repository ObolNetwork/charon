// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package fetcher_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/fetcher"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestFetchAttester(t *testing.T) {
	ctx := context.Background()

	const (
		slot    = 1
		vIdxA   = 2
		vIdxB   = 3
		notZero = 99 // Validation require non-zero values
	)

	pubkeysByIdx := map[eth2p0.ValidatorIndex]core.PubKey{
		vIdxA: testutil.RandomCorePubKey(t),
		vIdxB: testutil.RandomCorePubKey(t),
	}

	dutyA := eth2v1.AttesterDuty{
		Slot:             slot,
		ValidatorIndex:   vIdxA,
		CommitteeIndex:   vIdxA,
		CommitteeLength:  notZero,
		CommitteesAtSlot: notZero,
	}

	dutyB := eth2v1.AttesterDuty{
		Slot:             slot,
		ValidatorIndex:   vIdxB,
		CommitteeIndex:   vIdxB,
		CommitteeLength:  notZero,
		CommitteesAtSlot: notZero,
	}

	defSet := core.DutyDefinitionSet{
		pubkeysByIdx[vIdxA]: core.NewAttesterDefinition(&dutyA),
		pubkeysByIdx[vIdxB]: core.NewAttesterDefinition(&dutyB),
	}
	duty := core.NewAttesterDuty(slot)
	bmock, err := beaconmock.New()
	require.NoError(t, err)
	fetch, err := fetcher.New(bmock, nil)
	require.NoError(t, err)

	fetch.Subscribe(func(ctx context.Context, resDuty core.Duty, resDataSet core.UnsignedDataSet) error {
		require.Equal(t, duty, resDuty)
		require.Len(t, resDataSet, 2)

		dutyDataA := resDataSet[pubkeysByIdx[vIdxA]].(core.AttestationData)
		require.EqualValues(t, slot, dutyDataA.Data.Slot)
		require.EqualValues(t, vIdxA, dutyDataA.Data.Index)
		require.EqualValues(t, dutyA, dutyDataA.Duty)

		dutyDataB := resDataSet[pubkeysByIdx[vIdxB]].(core.AttestationData)
		require.EqualValues(t, slot, dutyDataB.Data.Slot)
		require.EqualValues(t, vIdxB, dutyDataB.Data.Index)
		require.EqualValues(t, dutyB, dutyDataB.Duty)

		return nil
	})

	err = fetch.Fetch(ctx, duty, defSet)
	require.NoError(t, err)
}

func TestFetchAggregator(t *testing.T) {
	ctx := context.Background()

	const (
		slot                = 1
		vIdxA               = 2
		vIdxB               = 3
		commLenAggregator   = 0
		commLenNoAggregator = math.MaxUint64
	)

	nilAggregate := false

	duty := core.NewAggregatorDuty(slot)

	pubkeysByIdx := map[eth2p0.ValidatorIndex]core.PubKey{
		vIdxA: testutil.RandomCorePubKey(t),
		vIdxB: testutil.RandomCorePubKey(t),
	}

	attA := testutil.RandomAttestation()
	attB := testutil.RandomAttestation()
	attByCommIdx := map[uint64]*eth2p0.Attestation{
		uint64(attA.Data.Index): attA,
		uint64(attB.Data.Index): attB,
	}

	newDefSet := func(commLength uint64, sameCommitteeIndex bool) core.DutyDefinitionSet {
		dutyA := testutil.RandomAttestationDuty(t)
		dutyA.CommitteeLength = commLength
		dutyA.CommitteeIndex = attA.Data.Index
		dutyB := testutil.RandomAttestationDuty(t)
		dutyB.CommitteeLength = commLength
		dutyB.CommitteeIndex = attB.Data.Index

		if sameCommitteeIndex {
			dutyB.CommitteeIndex = attA.Data.Index
			attB.Data.Index = attA.Data.Index
		}

		return map[core.PubKey]core.DutyDefinition{
			pubkeysByIdx[vIdxA]: core.NewAttesterDefinition(dutyA),
			pubkeysByIdx[vIdxB]: core.NewAttesterDefinition(dutyB),
		}
	}

	signedCommSubByPubKey := map[core.PubKey]core.SignedData{
		pubkeysByIdx[vIdxA]: testutil.RandomCoreBeaconCommitteeSelection(),
		pubkeysByIdx[vIdxB]: testutil.RandomCoreBeaconCommitteeSelection(),
	}

	bmock, err := beaconmock.New()
	require.NoError(t, err)

	var aggAttCallCount int
	bmock.AggregateAttestationFunc = func(ctx context.Context, slot eth2p0.Slot, root eth2p0.Root) (*eth2p0.Attestation, error) {
		aggAttCallCount--
		if nilAggregate {
			return nil, nil //nolint:nilnil // This reproduces what go-eth2-client does
		}
		for _, att := range attByCommIdx {
			dataRoot, err := att.Data.HashTreeRoot()
			require.NoError(t, err)
			if dataRoot == root {
				return att, nil
			}
		}

		return nil, errors.New("expected unknown root")
	}

	fetch, err := fetcher.New(bmock, nil)
	require.NoError(t, err)

	fetch.RegisterAggSigDB(func(ctx context.Context, duty core.Duty, key core.PubKey) (core.SignedData, error) {
		require.Equal(t, core.NewPrepareAggregatorDuty(slot), duty)

		return signedCommSubByPubKey[key], nil
	})

	fetch.RegisterAwaitAttData(func(ctx context.Context, slot uint64, commIdx uint64) (*eth2p0.AttestationData, error) {
		return attByCommIdx[commIdx].Data, nil
	})

	done := errors.New("done")
	fetch.Subscribe(func(ctx context.Context, resDuty core.Duty, resDataSet core.UnsignedDataSet) error {
		require.Equal(t, duty, resDuty)
		require.Len(t, resDataSet, 2)

		for _, aggAtt := range resDataSet {
			aggregated, ok := aggAtt.(core.AggregatedAttestation)
			require.True(t, ok)

			att, ok := attByCommIdx[uint64(aggregated.Attestation.Data.Index)]
			require.True(t, ok)
			require.Equal(t, aggregated.Attestation, *att)
		}

		return done
	})

	tests := []struct {
		name            string
		aggAttCallCount int // Number of time aggregate attestation is queried from beacon node.
		sameCommittee   bool
		nilAggregate    bool
		commLen         uint64
		expectedErr     string
	}{
		{
			name:            "aggregator with different committee index",
			commLen:         commLenAggregator,
			aggAttCallCount: 2,
			expectedErr:     "done",
		},
		{
			name:            "aggregator with same committee index",
			sameCommittee:   true,
			commLen:         commLenAggregator,
			aggAttCallCount: 1,
			expectedErr:     "done",
		},
		{
			name:    "no aggregator",
			commLen: commLenNoAggregator,
		},
		{
			name:            "nil aggregate attestation response",
			aggAttCallCount: 1,
			nilAggregate:    true,
			expectedErr:     "aggregate attestation not found by root (retryable)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nilAggregate = test.nilAggregate
			aggAttCallCount = test.aggAttCallCount
			err = fetch.Fetch(ctx, duty, newDefSet(test.commLen, test.sameCommittee))

			if test.expectedErr != "" {
				require.ErrorContains(t, err, test.expectedErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, 0, aggAttCallCount)
		})
	}
}

func TestFetchBlocks(t *testing.T) {
	ctx := context.Background()

	const (
		slot             = 1
		vIdxA            = 2
		vIdxB            = 3
		feeRecipientAddr = "0x0000000000000000000000000000000000000000"
	)

	pubkeysByIdx := map[eth2p0.ValidatorIndex]core.PubKey{
		vIdxA: testutil.RandomCorePubKey(t),
		vIdxB: testutil.RandomCorePubKey(t),
	}

	dutyA := eth2v1.ProposerDuty{
		Slot:           slot,
		ValidatorIndex: vIdxA,
	}
	dutyB := eth2v1.ProposerDuty{
		Slot:           slot,
		ValidatorIndex: vIdxB,
	}
	defSet := core.DutyDefinitionSet{
		pubkeysByIdx[vIdxA]: core.NewProposerDefinition(&dutyA),
		pubkeysByIdx[vIdxB]: core.NewProposerDefinition(&dutyB),
	}

	randaoA := testutil.RandomCoreSignature()
	randaoB := testutil.RandomCoreSignature()
	randaoByPubKey := map[core.PubKey]core.SignedData{
		pubkeysByIdx[vIdxA]: randaoA,
		pubkeysByIdx[vIdxB]: randaoB,
	}

	bmock, err := beaconmock.New()
	require.NoError(t, err)

	t.Run("fetch DutyProposer", func(t *testing.T) {
		duty := core.NewProposerDuty(slot)
		fetch, err := fetcher.New(bmock, func(core.PubKey) string {
			return feeRecipientAddr
		})
		require.NoError(t, err)

		fetch.RegisterAggSigDB(func(ctx context.Context, duty core.Duty, key core.PubKey) (core.SignedData, error) {
			return randaoByPubKey[key], nil
		})

		fetch.Subscribe(func(ctx context.Context, resDuty core.Duty, resDataSet core.UnsignedDataSet) error {
			require.Equal(t, duty, resDuty)
			require.Len(t, resDataSet, 2)

			dutyDataA := resDataSet[pubkeysByIdx[vIdxA]].(core.VersionedProposal)
			slotA, err := dutyDataA.Slot()
			require.NoError(t, err)
			require.EqualValues(t, slot, slotA)
			require.Equal(t, feeRecipientAddr, fmt.Sprintf("%#x", dutyDataA.Capella.Body.ExecutionPayload.FeeRecipient))
			assertRandao(t, randaoByPubKey[pubkeysByIdx[vIdxA]].Signature().ToETH2(), dutyDataA)

			dutyDataB := resDataSet[pubkeysByIdx[vIdxB]].(core.VersionedProposal)
			slotB, err := dutyDataB.Slot()
			require.NoError(t, err)
			require.EqualValues(t, slot, slotB)
			require.Equal(t, feeRecipientAddr, fmt.Sprintf("%#x", dutyDataB.Capella.Body.ExecutionPayload.FeeRecipient))
			assertRandao(t, randaoByPubKey[pubkeysByIdx[vIdxB]].Signature().ToETH2(), dutyDataB)

			return nil
		})

		err = fetch.Fetch(ctx, duty, defSet)
		require.NoError(t, err)
	})

	t.Run("fetch DutyBuilderProposer", func(t *testing.T) {
		duty := core.NewBuilderProposerDuty(slot)
		fetch, err := fetcher.New(bmock, func(core.PubKey) string {
			return feeRecipientAddr
		})
		require.NoError(t, err)

		fetch.RegisterAggSigDB(func(ctx context.Context, duty core.Duty, key core.PubKey) (core.SignedData, error) {
			return randaoByPubKey[key], nil
		})

		fetch.Subscribe(func(ctx context.Context, resDuty core.Duty, resDataSet core.UnsignedDataSet) error {
			require.Equal(t, duty, resDuty)
			require.Len(t, resDataSet, 2)

			dutyDataA := resDataSet[pubkeysByIdx[vIdxA]].(core.VersionedBlindedProposal)
			slotA, err := dutyDataA.Slot()
			require.NoError(t, err)
			require.EqualValues(t, slot, slotA)
			require.Equal(t, feeRecipientAddr, fmt.Sprintf("%#x", dutyDataA.Capella.Body.ExecutionPayloadHeader.FeeRecipient))
			assertRandaoBlindedBlock(t, randaoByPubKey[pubkeysByIdx[vIdxA]].Signature().ToETH2(), dutyDataA)

			dutyDataB := resDataSet[pubkeysByIdx[vIdxB]].(core.VersionedBlindedProposal)
			slotB, err := dutyDataB.Slot()
			require.NoError(t, err)
			require.EqualValues(t, slot, slotB)
			require.Equal(t, feeRecipientAddr, fmt.Sprintf("%#x", dutyDataB.Capella.Body.ExecutionPayloadHeader.FeeRecipient))
			assertRandaoBlindedBlock(t, randaoByPubKey[pubkeysByIdx[vIdxB]].Signature().ToETH2(), dutyDataB)

			return nil
		})

		err = fetch.Fetch(ctx, duty, defSet)
		require.NoError(t, err)
	})
}

func TestFetchSyncContribution(t *testing.T) {
	ctx := context.Background()

	const (
		slot        = 1
		vIdxA       = 2
		vIdxB       = 3
		subCommIdxA = 4
		subCommIdxB = 5
	)

	var (
		duty             = core.NewSyncContributionDuty(slot)
		beaconBlockRootA = testutil.RandomRoot()
		beaconBlockRootB = testutil.RandomRoot()
	)

	pubkeysByIdx := map[eth2p0.ValidatorIndex]core.PubKey{
		vIdxA: testutil.RandomCorePubKey(t),
		vIdxB: testutil.RandomCorePubKey(t),
	}

	// Construct duty definition set.
	defSet := map[core.PubKey]core.DutyDefinition{
		pubkeysByIdx[vIdxA]: core.NewSyncCommitteeDefinition(testutil.RandomSyncCommitteeDuty(t)),
		pubkeysByIdx[vIdxB]: core.NewSyncCommitteeDefinition(testutil.RandomSyncCommitteeDuty(t)),
	}

	var (
		// Signatures corresponding to aggregators. Refer https://github.com/prysmaticlabs/prysm/blob/39a7988e9edbed5b517229b4d66c2a8aab7c7b4d/beacon-chain/sync/validate_sync_contribution_proof_test.go#L460.
		sigA = "a9dbd88a49a7269e91b8ef1296f1e07f87fed919d51a446b67122bfdfd61d23f3f929fc1cd5209bd6862fd60f739b27213fb0a8d339f7f081fc84281f554b190bb49cc97a6b3364e622af9e7ca96a97fe2b766f9e746dead0b33b58473d91562"
		sigB = "99e60f20dde4d4872b048d703f1943071c20213d504012e7e520c229da87661803b9f139b9a0c5be31de3cef6821c080125aed38ebaf51ba9a2e9d21d7fbf2903577983109d097a8599610a92c0305408d97c1fd4b0b2d1743fb4eedf5443f99"
	)
	// Construct sync committee selections.
	selectionA := &eth2exp.SyncCommitteeSelection{
		ValidatorIndex:    vIdxA,
		Slot:              slot,
		SubcommitteeIndex: subCommIdxA,
		SelectionProof:    blsSigFromHex(t, sigA),
	}

	selectionB := &eth2exp.SyncCommitteeSelection{
		ValidatorIndex:    vIdxB,
		Slot:              slot,
		SubcommitteeIndex: subCommIdxB,
		SelectionProof:    blsSigFromHex(t, sigB),
	}
	commSelectionsByPubkey := map[core.PubKey]core.SignedData{
		pubkeysByIdx[vIdxA]: core.NewSyncCommitteeSelection(selectionA),
		pubkeysByIdx[vIdxB]: core.NewSyncCommitteeSelection(selectionB),
	}

	// Construct sync committee messages.
	msgA := testutil.RandomSyncCommitteeMessage()
	msgA.BeaconBlockRoot = beaconBlockRootA
	msgB := testutil.RandomSyncCommitteeMessage()
	msgB.BeaconBlockRoot = beaconBlockRootB
	syncMsgsByPubkey := map[core.PubKey]core.SignedData{
		pubkeysByIdx[vIdxA]: core.NewSignedSyncMessage(msgA),
		pubkeysByIdx[vIdxB]: core.NewSignedSyncMessage(msgB),
	}

	t.Run("contribution aggregator", func(t *testing.T) {
		// Construct beaconmock.
		bmock, err := beaconmock.New()
		require.NoError(t, err)

		bmock.SyncCommitteeContributionFunc = func(ctx context.Context, resSlot eth2p0.Slot, subcommitteeIndex uint64, beaconBlockRoot eth2p0.Root) (*altair.SyncCommitteeContribution, error) {
			require.Equal(t, eth2p0.Slot(slot), resSlot)

			var (
				signedMsg       core.SignedSyncMessage
				signedSelection core.SyncCommitteeSelection
			)
			for _, msg := range syncMsgsByPubkey {
				m, ok := msg.(core.SignedSyncMessage)
				require.True(t, ok)
				if m.BeaconBlockRoot == beaconBlockRoot {
					signedMsg = m
				}
			}
			require.NotNil(t, signedMsg)

			for _, selection := range commSelectionsByPubkey {
				s, ok := selection.(core.SyncCommitteeSelection)
				require.True(t, ok)
				if s.SubcommitteeIndex == eth2p0.CommitteeIndex(subcommitteeIndex) {
					signedSelection = s
				}
			}
			require.NotNil(t, signedSelection)

			return &altair.SyncCommitteeContribution{
				Slot:              slot,
				BeaconBlockRoot:   beaconBlockRoot,
				SubcommitteeIndex: subcommitteeIndex,
				AggregationBits:   bitfield.Bitvector128(testutil.RandomBitList(1)),
				Signature:         testutil.RandomEth2Signature(),
			}, nil
		}

		// Construct fetcher component.
		fetch, err := fetcher.New(bmock, nil)
		require.NoError(t, err)

		fetch.RegisterAggSigDB(func(ctx context.Context, duty core.Duty, key core.PubKey) (core.SignedData, error) {
			if duty.Type == core.DutyPrepareSyncContribution {
				require.Equal(t, core.NewPrepareSyncContributionDuty(slot), duty)
				return commSelectionsByPubkey[key], nil
			}

			if duty.Type == core.DutySyncMessage {
				require.Equal(t, core.NewSyncMessageDuty(slot), duty)
				return syncMsgsByPubkey[key], nil
			}

			return nil, errors.New("unsupported duty")
		})

		fetch.Subscribe(func(ctx context.Context, resDuty core.Duty, resDataSet core.UnsignedDataSet) error {
			require.Equal(t, duty, resDuty)
			require.Len(t, resDataSet, 2)

			for pubkey, data := range resDataSet {
				contribution, ok := data.(core.SyncContribution)
				require.True(t, ok)
				require.Equal(t, eth2p0.Slot(slot), contribution.Slot)

				selection, ok := commSelectionsByPubkey[pubkey].(core.SyncCommitteeSelection)
				require.True(t, ok)

				for vIdx, pk := range pubkeysByIdx {
					if pubkey == pk {
						require.Equal(t, selection.ValidatorIndex, vIdx)
					}
				}
				require.Equal(t, eth2p0.Slot(slot), selection.Slot)
				require.Equal(t, eth2p0.CommitteeIndex(contribution.SubcommitteeIndex), selection.SubcommitteeIndex)

				if selection.ValidatorIndex == eth2p0.ValidatorIndex(vIdxA) {
					require.Equal(t, eth2p0.CommitteeIndex(subCommIdxA), selection.SubcommitteeIndex)
				} else if selection.ValidatorIndex == eth2p0.ValidatorIndex(vIdxB) {
					require.Equal(t, eth2p0.CommitteeIndex(subCommIdxB), selection.SubcommitteeIndex)
				}

				message, ok := syncMsgsByPubkey[pubkey].(core.SignedSyncMessage)
				require.True(t, ok)
				require.Equal(t, message.BeaconBlockRoot, contribution.BeaconBlockRoot)
			}

			return nil
		})

		err = fetch.Fetch(ctx, duty, defSet)
		require.NoError(t, err)
	})

	t.Run("not contribution aggregator", func(t *testing.T) {
		// Construct beaconmock.
		bmock, err := beaconmock.New()
		require.NoError(t, err)

		// Construct fetcher component.
		fetch, err := fetcher.New(bmock, nil)
		require.NoError(t, err)

		fetch.RegisterAggSigDB(func(ctx context.Context, duty core.Duty, key core.PubKey) (core.SignedData, error) {
			if duty.Type == core.DutyPrepareSyncContribution {
				require.Equal(t, core.NewPrepareSyncContributionDuty(slot), duty)

				// Signature corresponding to a non-aggregator. Refer https://github.com/prysmaticlabs/prysm/blob/39a7988e9edbed5b517229b4d66c2a8aab7c7b4d/beacon-chain/sync/validate_sync_contribution_proof_test.go#L336
				sig := "b9251a82040d4620b8c5665f328ee6c2eaa02d31d71d153f4abba31a7922a981e541e85283f0ced387d26e86aef9386d18c6982b9b5f8759882fe7f25a328180d86e146994ef19d28bc1432baf29751dec12b5f3d65dbbe224d72cf900c6831a"
				resp := blsSigFromHex(t, sig)
				selection := &eth2exp.SyncCommitteeSelection{
					SelectionProof: resp,
				}

				return core.NewSyncCommitteeSelection(selection), nil
			}

			return nil, errors.New("unsupported duty")
		})

		err = fetch.Fetch(ctx, duty, defSet)
		require.NoError(t, err)
	})

	t.Run("fetch contribution data error", func(t *testing.T) {
		// Construct beaconmock.
		bmock, err := beaconmock.New()
		require.NoError(t, err)

		// Construct fetcher component.
		fetch, err := fetcher.New(bmock, nil)
		require.NoError(t, err)

		fetch.RegisterAggSigDB(func(ctx context.Context, duty core.Duty, key core.PubKey) (core.SignedData, error) {
			return nil, errors.New("error")
		})

		err = fetch.Fetch(ctx, duty, defSet)
		require.Error(t, err)
		require.ErrorContains(t, err, "fetch contribution data")
		require.ErrorContains(t, err, "error")
	})
}

func assertRandao(t *testing.T, randao eth2p0.BLSSignature, block core.VersionedProposal) {
	t.Helper()

	switch block.Version {
	case eth2spec.DataVersionPhase0:
		require.EqualValues(t, randao, block.Phase0.Body.RANDAOReveal)
	case eth2spec.DataVersionAltair:
		require.EqualValues(t, randao, block.Altair.Body.RANDAOReveal)
	case eth2spec.DataVersionBellatrix:
		require.EqualValues(t, randao, block.Bellatrix.Body.RANDAOReveal)
	case eth2spec.DataVersionCapella:
		require.EqualValues(t, randao, block.Capella.Body.RANDAOReveal)
	case eth2spec.DataVersionDeneb:
		require.EqualValues(t, randao, block.Deneb.Block.Body.RANDAOReveal)
	default:
		require.Fail(t, "invalid block")
	}
}

func assertRandaoBlindedBlock(t *testing.T, randao eth2p0.BLSSignature, block core.VersionedBlindedProposal) {
	t.Helper()

	switch block.Version {
	case eth2spec.DataVersionBellatrix:
		require.EqualValues(t, randao, block.Bellatrix.Body.RANDAOReveal)
	case eth2spec.DataVersionCapella:
		require.EqualValues(t, randao, block.Capella.Body.RANDAOReveal)
	case eth2spec.DataVersionDeneb:
		require.EqualValues(t, randao, block.Deneb.Body.RANDAOReveal)
	default:
		require.Fail(t, "invalid block")
	}
}

// blsSigFromHex returns the BLS signature from the input hex signature.
func blsSigFromHex(t *testing.T, sig string) eth2p0.BLSSignature {
	t.Helper()

	s, err := hex.DecodeString(sig)
	require.NoError(t, err)

	var resp eth2p0.BLSSignature
	copy(resp[:], s)

	return resp
}
