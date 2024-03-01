// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dutydb_test

import (
	"context"
	"runtime"
	"sync"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/dutydb"
	"github.com/obolnetwork/charon/testutil"
)

func TestShutdown(t *testing.T) {
	db := dutydb.NewMemDB(new(testDeadliner))

	errChan := make(chan error, 1)
	go func() {
		_, err := db.AwaitProposal(context.Background(), 999)
		errChan <- err
	}()

	runtime.Gosched()
	db.Shutdown()

	err := <-errChan
	require.Error(t, err)
	require.Contains(t, err.Error(), "shutdown")
}

func TestMemDB(t *testing.T) {
	ctx := context.Background()
	db := dutydb.NewMemDB(new(testDeadliner))

	// Nothing in the DB, so expect error
	_, err := db.PubKeyByAttestation(ctx, 0, 0, 0)
	require.Error(t, err)

	const (
		queries = 3
		notZero = 99

		slot        = 123
		commIdx     = 456
		commLen     = 8
		vIdxA       = 1
		vIdxB       = 2
		valCommIdxA = vIdxA
		valCommIdxB = vIdxB
	)
	// Store the same attestation (same slot and committee) for two validators.

	pubkeysByIdx := map[eth2p0.ValidatorIndex]core.PubKey{
		vIdxA: testutil.RandomCorePubKey(t),
		vIdxB: testutil.RandomCorePubKey(t),
	}

	// Kick of some queries, it should return when the data is populated.
	awaitResponse := make(chan *eth2p0.AttestationData)
	for i := 0; i < queries; i++ {
		go func() {
			data, err := db.AwaitAttestation(ctx, slot, commIdx)
			require.NoError(t, err)
			awaitResponse <- data
		}()
	}

	// Store this attestation
	attData := eth2p0.AttestationData{
		Slot:   slot,
		Index:  commIdx,
		Source: &eth2p0.Checkpoint{},
		Target: &eth2p0.Checkpoint{},
	}

	duty := core.Duty{Slot: slot, Type: core.DutyAttester}

	// The two validators have similar unsigned data, just the ValidatorCommitteeIndex is different.
	unsignedA := core.AttestationData{
		Data: attData,
		Duty: eth2v1.AttesterDuty{
			CommitteeLength:         commLen,
			ValidatorCommitteeIndex: valCommIdxA,
			CommitteesAtSlot:        notZero,
		},
	}
	unsignedB := core.AttestationData{
		Data: attData,
		Duty: eth2v1.AttesterDuty{
			CommitteeLength:         commLen,
			ValidatorCommitteeIndex: valCommIdxB,
			CommitteesAtSlot:        notZero,
		},
	}

	// Store it
	err = db.Store(ctx, duty, core.UnsignedDataSet{pubkeysByIdx[vIdxA]: unsignedA, pubkeysByIdx[vIdxB]: unsignedB})
	require.NoError(t, err)

	// Store one validator again to test idempotent inserts
	err = db.Store(ctx, duty, core.UnsignedDataSet{pubkeysByIdx[vIdxA]: unsignedA})
	require.NoError(t, err)

	// Get and assert the attQuery responses.
	for i := 0; i < queries; i++ {
		actual := <-awaitResponse
		require.Equal(t, attData.String(), actual.String())
	}

	// Assert that two pubkeys can be resolved.
	pkA, err := db.PubKeyByAttestation(ctx, uint64(attData.Slot), uint64(attData.Index), valCommIdxA)
	require.NoError(t, err)
	require.Equal(t, pubkeysByIdx[vIdxA], pkA)

	pkB, err := db.PubKeyByAttestation(ctx, uint64(attData.Slot), uint64(attData.Index), valCommIdxB)
	require.NoError(t, err)
	require.Equal(t, pubkeysByIdx[vIdxB], pkB)
}

func TestMemDBProposer(t *testing.T) {
	ctx := context.Background()
	db := dutydb.NewMemDB(new(testDeadliner))

	const queries = 3
	slots := [queries]uint64{123, 456, 789}

	type response struct {
		block *eth2api.VersionedProposal
	}
	var awaitResponse [queries]chan response
	for i := 0; i < queries; i++ {
		awaitResponse[i] = make(chan response)
		go func(slot int) {
			block, err := db.AwaitProposal(ctx, slots[slot])
			require.NoError(t, err)
			awaitResponse[slot] <- response{block: block}
		}(i)
	}

	proposals := make([]*eth2api.VersionedProposal, queries)
	pubkeysByIdx := make(map[eth2p0.ValidatorIndex]core.PubKey)
	for i := 0; i < queries; i++ {
		proposals[i] = &eth2api.VersionedProposal{
			Version:   eth2spec.DataVersionBellatrix,
			Bellatrix: testutil.RandomBellatrixBeaconBlock(),
		}
		proposals[i].Bellatrix.Slot = eth2p0.Slot(slots[i])
		proposals[i].Bellatrix.ProposerIndex = eth2p0.ValidatorIndex(i)
		pubkeysByIdx[eth2p0.ValidatorIndex(i)] = testutil.RandomCorePubKey(t)
	}

	// Store the Blocks
	for i := 0; i < queries; i++ {
		unsigned, err := core.NewVersionedProposal(proposals[i])
		require.NoError(t, err)

		duty := core.Duty{Slot: slots[i], Type: core.DutyProposer}
		err = db.Store(ctx, duty, core.UnsignedDataSet{
			pubkeysByIdx[eth2p0.ValidatorIndex(i)]: unsigned,
		})
		require.NoError(t, err)
	}

	// Get and assert the proQuery responses
	for i := 0; i < queries; i++ {
		actualData := <-awaitResponse[i]
		require.Equal(t, proposals[i], actualData.block)
	}
}

func TestMemDBUniversalProposer(t *testing.T) {
	ctx := context.Background()
	db := dutydb.NewMemDB(new(testDeadliner))

	const queries = 3
	slots := [queries]uint64{123, 456, 789}

	type response struct {
		block *eth2api.VersionedUniversalProposal
	}
	var awaitResponse [queries]chan response
	for i := 0; i < queries; i++ {
		awaitResponse[i] = make(chan response)
		go func(slot int) {
			block, err := db.AwaitUniversalProposal(ctx, slots[slot])
			require.NoError(t, err)
			awaitResponse[slot] <- response{block: block}
		}(i)
	}

	proposals := make([]*eth2api.VersionedUniversalProposal, queries)
	pubkeysByIdx := make(map[eth2p0.ValidatorIndex]core.PubKey)
	for i := 0; i < queries; i++ {
		proposals[i] = &eth2api.VersionedUniversalProposal{
			Proposal: &eth2api.VersionedProposal{
				Version:   eth2spec.DataVersionBellatrix,
				Bellatrix: testutil.RandomBellatrixBeaconBlock(),
			},
		}
		proposals[i].Proposal.Bellatrix.Slot = eth2p0.Slot(slots[i])
		proposals[i].Proposal.Bellatrix.ProposerIndex = eth2p0.ValidatorIndex(i)
		pubkeysByIdx[eth2p0.ValidatorIndex(i)] = testutil.RandomCorePubKey(t)
	}

	// Store the Blocks
	for i := 0; i < queries; i++ {
		unsigned, err := core.NewVersionedUniversalProposal(proposals[i])
		require.NoError(t, err)

		duty := core.Duty{Slot: slots[i], Type: core.DutyUniversalProposer}
		err = db.Store(ctx, duty, core.UnsignedDataSet{
			pubkeysByIdx[eth2p0.ValidatorIndex(i)]: unsigned,
		})
		require.NoError(t, err)
	}

	// Get and assert the proQuery responses
	for i := 0; i < queries; i++ {
		actualData := <-awaitResponse[i]
		require.Equal(t, proposals[i], actualData.block)
	}
}

func TestMemDBAggregator(t *testing.T) {
	ctx := context.Background()
	db := dutydb.NewMemDB(new(testDeadliner))

	const queries = 3

	for i := 0; i < queries; i++ {
		agg := testutil.RandomAttestation()
		set := core.UnsignedDataSet{
			testutil.RandomCorePubKey(t): core.NewAggregatedAttestation(agg),
		}
		slot := uint64(agg.Data.Slot)
		go func() {
			err := db.Store(ctx, core.NewAggregatorDuty(slot), set)
			require.NoError(t, err)
		}()

		root, err := agg.Data.HashTreeRoot()
		require.NoError(t, err)
		resp, err := db.AwaitAggAttestation(ctx, slot, root)
		require.NoError(t, err)
		require.Equal(t, agg, resp)
	}
}

func TestMemDBSyncContribution(t *testing.T) {
	t.Run("await sync contribution", func(t *testing.T) {
		ctx := context.Background()
		db := dutydb.NewMemDB(new(testDeadliner))

		const queries = 3

		for i := 0; i < queries; i++ {
			contrib := testutil.RandomSyncCommitteeContribution()
			set := core.UnsignedDataSet{
				testutil.RandomCorePubKey(t): core.NewSyncContribution(contrib),
			}

			var (
				slot            = uint64(contrib.Slot)
				subcommIdx      = contrib.SubcommitteeIndex
				beaconBlockRoot = contrib.BeaconBlockRoot
			)

			go func() {
				err := db.Store(ctx, core.NewSyncContributionDuty(slot), set)
				require.NoError(t, err)
			}()

			resp, err := db.AwaitSyncContribution(ctx, slot, subcommIdx, beaconBlockRoot)
			require.NoError(t, err)
			require.Equal(t, contrib, resp)
		}
	})

	t.Run("dutydb shutdown", func(t *testing.T) {
		db := dutydb.NewMemDB(new(testDeadliner))
		db.Shutdown()

		resp, err := db.AwaitSyncContribution(context.Background(), 0, 0, testutil.RandomRoot())
		require.Error(t, err)
		require.ErrorContains(t, err, "dutydb shutdown")
		require.Nil(t, resp)
	})

	t.Run("clashing sync contributions", func(t *testing.T) {
		const (
			slot       = 123
			subcommIdx = 1
		)

		var (
			ctx             = context.Background()
			db              = dutydb.NewMemDB(new(testDeadliner))
			duty            = core.NewSyncContributionDuty(slot)
			pubkey          = testutil.RandomCorePubKey(t)
			beaconBlockRoot = testutil.RandomRoot()
		)

		// Construct sync contributions.
		contrib1 := testutil.RandomSyncCommitteeContribution()
		contrib1.Slot = slot
		contrib1.SubcommitteeIndex = subcommIdx
		contrib1.BeaconBlockRoot = beaconBlockRoot
		unsigned1 := core.NewSyncContribution(contrib1)

		contrib2 := testutil.RandomSyncCommitteeContribution()
		contrib2.Slot = slot
		contrib2.SubcommitteeIndex = subcommIdx
		contrib2.BeaconBlockRoot = beaconBlockRoot
		unsigned2 := core.NewSyncContribution(contrib2)

		// Store them.
		err := db.Store(ctx, duty, core.UnsignedDataSet{
			pubkey: unsigned1,
		})
		require.NoError(t, err)

		err = db.Store(ctx, duty, core.UnsignedDataSet{
			pubkey: unsigned2,
		})
		require.Error(t, err)
		require.ErrorContains(t, err, "clashing sync contributions")
	})

	t.Run("invalid unsigned sync contribution", func(t *testing.T) {
		var (
			db   = dutydb.NewMemDB(new(testDeadliner))
			ctx  = context.Background()
			duty = core.NewSyncContributionDuty(0)
		)

		err := db.Store(ctx, duty, core.UnsignedDataSet{
			testutil.RandomCorePubKey(t): core.NewAggregatedAttestation(testutil.RandomAttestation()),
		})
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid unsigned sync committee contribution")
	})
}

func TestMemDBClashingBlocks(t *testing.T) {
	ctx := context.Background()
	db := dutydb.NewMemDB(new(testDeadliner))

	const slot = 123
	block1 := &eth2api.VersionedProposal{
		Version:   eth2spec.DataVersionBellatrix,
		Bellatrix: testutil.RandomBellatrixBeaconBlock(),
	}
	block1.Bellatrix.Slot = eth2p0.Slot(slot)
	block2 := &eth2api.VersionedProposal{
		Version:   eth2spec.DataVersionBellatrix,
		Bellatrix: testutil.RandomBellatrixBeaconBlock(),
	}
	block2.Bellatrix.Slot = eth2p0.Slot(slot)
	pubkey := testutil.RandomCorePubKey(t)

	// Encode the Blocks
	unsigned1, err := core.NewVersionedProposal(block1)
	require.NoError(t, err)

	unsigned2, err := core.NewVersionedProposal(block2)
	require.NoError(t, err)

	// Store the Blocks
	duty := core.Duty{Slot: slot, Type: core.DutyProposer}
	err = db.Store(ctx, duty, core.UnsignedDataSet{
		pubkey: unsigned1,
	})
	require.NoError(t, err)

	err = db.Store(ctx, duty, core.UnsignedDataSet{
		pubkey: unsigned2,
	})
	require.ErrorContains(t, err, "clashing blocks")
}

func TestMemDBClashingUniversalBlocks(t *testing.T) {
	ctx := context.Background()
	db := dutydb.NewMemDB(new(testDeadliner))

	const slot = 123
	block1 := &eth2api.VersionedUniversalProposal{
		Proposal: &eth2api.VersionedProposal{
			Version:   eth2spec.DataVersionBellatrix,
			Bellatrix: testutil.RandomBellatrixBeaconBlock(),
		},
	}
	block1.Proposal.Bellatrix.Slot = eth2p0.Slot(slot)
	block2 := &eth2api.VersionedUniversalProposal{
		Proposal: &eth2api.VersionedProposal{
			Version:   eth2spec.DataVersionBellatrix,
			Bellatrix: testutil.RandomBellatrixBeaconBlock(),
		},
	}
	block2.Proposal.Bellatrix.Slot = eth2p0.Slot(slot)
	pubkey := testutil.RandomCorePubKey(t)

	// Encode the Blocks
	unsigned1, err := core.NewVersionedUniversalProposal(block1)
	require.NoError(t, err)

	unsigned2, err := core.NewVersionedUniversalProposal(block2)
	require.NoError(t, err)

	// Store the Blocks
	duty := core.Duty{Slot: slot, Type: core.DutyUniversalProposer}
	err = db.Store(ctx, duty, core.UnsignedDataSet{
		pubkey: unsigned1,
	})
	require.NoError(t, err)

	err = db.Store(ctx, duty, core.UnsignedDataSet{
		pubkey: unsigned2,
	})
	require.ErrorContains(t, err, "clashing blocks")
}

func TestMemDBClashProposer(t *testing.T) {
	ctx := context.Background()
	db := dutydb.NewMemDB(new(testDeadliner))

	const slot = 123

	block := &eth2api.VersionedProposal{
		Version:   eth2spec.DataVersionBellatrix,
		Bellatrix: testutil.RandomBellatrixBeaconBlock(),
	}
	block.Bellatrix.Slot = eth2p0.Slot(slot)
	pubkey := testutil.RandomCorePubKey(t)

	// Encode the block
	unsigned, err := core.NewVersionedProposal(block)
	require.NoError(t, err)

	// Store the Blocks
	duty := core.Duty{Slot: slot, Type: core.DutyProposer}
	err = db.Store(ctx, duty, core.UnsignedDataSet{
		pubkey: unsigned,
	})
	require.NoError(t, err)

	// Store same block from same validator to test idempotent inserts
	err = db.Store(ctx, duty, core.UnsignedDataSet{
		pubkey: unsigned,
	})
	require.NoError(t, err)

	// Store a different block for the same slot
	block.Bellatrix.ProposerIndex++
	unsignedB, err := core.NewVersionedProposal(block)
	require.NoError(t, err)
	err = db.Store(ctx, duty, core.UnsignedDataSet{
		pubkey: unsignedB,
	})
	require.ErrorContains(t, err, "clashing blocks")
}

func TestMemDBClashUniversalProposer(t *testing.T) {
	ctx := context.Background()
	db := dutydb.NewMemDB(new(testDeadliner))

	const slot = 123

	block := &eth2api.VersionedUniversalProposal{
		Proposal: &eth2api.VersionedProposal{
			Version:   eth2spec.DataVersionBellatrix,
			Bellatrix: testutil.RandomBellatrixBeaconBlock(),
		},
	}
	block.Proposal.Bellatrix.Slot = eth2p0.Slot(slot)
	pubkey := testutil.RandomCorePubKey(t)

	// Encode the block
	unsigned, err := core.NewVersionedUniversalProposal(block)
	require.NoError(t, err)

	// Store the Blocks
	duty := core.Duty{Slot: slot, Type: core.DutyUniversalProposer}
	err = db.Store(ctx, duty, core.UnsignedDataSet{
		pubkey: unsigned,
	})
	require.NoError(t, err)

	// Store same block from same validator to test idempotent inserts
	err = db.Store(ctx, duty, core.UnsignedDataSet{
		pubkey: unsigned,
	})
	require.NoError(t, err)

	// Store a different block for the same slot
	block.Proposal.Bellatrix.ProposerIndex++
	unsignedB, err := core.NewVersionedUniversalProposal(block)
	require.NoError(t, err)
	err = db.Store(ctx, duty, core.UnsignedDataSet{
		pubkey: unsignedB,
	})
	require.ErrorContains(t, err, "clashing blocks")
}

func TestMemDBBuilderProposer(t *testing.T) {
	ctx := context.Background()
	db := dutydb.NewMemDB(new(testDeadliner))

	const queries = 3
	slots := [queries]uint64{123, 456, 789}

	type response struct {
		block *eth2api.VersionedBlindedProposal
	}
	var awaitResponse [queries]chan response
	for i := 0; i < queries; i++ {
		awaitResponse[i] = make(chan response)
		go func(slot int) {
			block, err := db.AwaitBlindedProposal(ctx, slots[slot])
			require.NoError(t, err)
			awaitResponse[slot] <- response{block: block}
		}(i)
	}

	blocks := make([]*eth2api.VersionedBlindedProposal, queries)
	pubkeysByIdx := make(map[eth2p0.ValidatorIndex]core.PubKey)
	for i := 0; i < queries; i++ {
		blocks[i] = &eth2api.VersionedBlindedProposal{
			Version:   eth2spec.DataVersionBellatrix,
			Bellatrix: testutil.RandomBellatrixBlindedBeaconBlock(),
		}
		blocks[i].Bellatrix.Slot = eth2p0.Slot(slots[i])
		blocks[i].Bellatrix.ProposerIndex = eth2p0.ValidatorIndex(i)
		pubkeysByIdx[eth2p0.ValidatorIndex(i)] = testutil.RandomCorePubKey(t)
	}

	// Store the Blocks
	for i := 0; i < queries; i++ {
		unsigned, err := core.NewVersionedBlindedProposal(blocks[i])
		require.NoError(t, err)

		duty := core.Duty{Slot: slots[i], Type: core.DutyBuilderProposer}
		err = db.Store(ctx, duty, core.UnsignedDataSet{
			pubkeysByIdx[eth2p0.ValidatorIndex(i)]: unsigned,
		})
		require.NoError(t, err)
	}

	// Get and assert the proQuery responses
	for i := 0; i < queries; i++ {
		actualData := <-awaitResponse[i]
		require.Equal(t, blocks[i], actualData.block)
	}
}

func TestMemDBClashingBlindedBlocks(t *testing.T) {
	ctx := context.Background()
	db := dutydb.NewMemDB(new(testDeadliner))

	const slot = 123
	block1 := &eth2api.VersionedBlindedProposal{
		Version:   eth2spec.DataVersionBellatrix,
		Bellatrix: testutil.RandomBellatrixBlindedBeaconBlock(),
	}
	block1.Bellatrix.Slot = eth2p0.Slot(slot)
	block2 := &eth2api.VersionedBlindedProposal{
		Version:   eth2spec.DataVersionBellatrix,
		Bellatrix: testutil.RandomBellatrixBlindedBeaconBlock(),
	}
	block2.Bellatrix.Slot = eth2p0.Slot(slot)
	pubkey := testutil.RandomCorePubKey(t)

	// Encode the Blocks
	unsigned1, err := core.NewVersionedBlindedProposal(block1)
	require.NoError(t, err)

	unsigned2, err := core.NewVersionedBlindedProposal(block2)
	require.NoError(t, err)

	// Store the Blocks
	duty := core.Duty{Slot: slot, Type: core.DutyBuilderProposer}
	err = db.Store(ctx, duty, core.UnsignedDataSet{
		pubkey: unsigned1,
	})
	require.NoError(t, err)

	err = db.Store(ctx, duty, core.UnsignedDataSet{
		pubkey: unsigned2,
	})
	require.ErrorContains(t, err, "clashing blinded blocks")
}

func TestMemDBClashBuilderProposer(t *testing.T) {
	ctx := context.Background()
	db := dutydb.NewMemDB(new(testDeadliner))

	const slot = 123

	block := &eth2api.VersionedBlindedProposal{
		Version:   eth2spec.DataVersionBellatrix,
		Bellatrix: testutil.RandomBellatrixBlindedBeaconBlock(),
	}
	block.Bellatrix.Slot = eth2p0.Slot(slot)
	pubkey := testutil.RandomCorePubKey(t)

	// Encode the block
	unsigned, err := core.NewVersionedBlindedProposal(block)
	require.NoError(t, err)

	// Store the Blocks
	duty := core.Duty{Slot: slot, Type: core.DutyBuilderProposer}
	err = db.Store(ctx, duty, core.UnsignedDataSet{
		pubkey: unsigned,
	})
	require.NoError(t, err)

	// Store same block from same validator to test idempotent inserts
	err = db.Store(ctx, duty, core.UnsignedDataSet{
		pubkey: unsigned,
	})
	require.NoError(t, err)

	// Store a different block for the same slot
	block.Bellatrix.ProposerIndex++
	unsignedB, err := core.NewVersionedBlindedProposal(block)
	require.NoError(t, err)
	err = db.Store(ctx, duty, core.UnsignedDataSet{
		pubkey: unsignedB,
	})
	require.ErrorContains(t, err, "clashing blinded blocks")
}

func TestDutyExpiry(t *testing.T) {
	ctx := context.Background()
	deadliner := &testDeadliner{ch: make(chan core.Duty, 10)}
	db := dutydb.NewMemDB(deadliner)

	// Add attestation data
	const slot = uint64(123)
	att1 := testutil.RandomCoreAttestationData(t)
	att1.Duty.Slot = eth2p0.Slot(slot)
	err := db.Store(ctx, core.NewAttesterDuty(slot), core.UnsignedDataSet{
		testutil.RandomCorePubKey(t): att1,
	})
	require.NoError(t, err)

	// Ensure it exists
	pk, err := db.PubKeyByAttestation(ctx, uint64(att1.Data.Slot), uint64(att1.Data.Index), att1.Duty.ValidatorCommitteeIndex)
	require.NoError(t, err)
	require.NotEmpty(t, pk)

	// Expire attestation
	deadliner.expire()

	versionedProposal := core.VersionedProposal{VersionedProposal: *testutil.RandomDenebVersionedProposal()}

	// Store another duty which deletes expired duties
	err = db.Store(ctx, core.NewProposerDuty(slot+1), core.UnsignedDataSet{
		testutil.RandomCorePubKey(t): versionedProposal,
	})
	require.NoError(t, err)

	// Pubkey not found.
	_, err = db.PubKeyByAttestation(ctx, uint64(att1.Data.Slot), uint64(att1.Data.Index), att1.Duty.ValidatorCommitteeIndex)
	require.Error(t, err)
}

// testDeadliner is a mock deadliner implementation.
type testDeadliner struct {
	mu    sync.Mutex
	added []core.Duty
	ch    chan core.Duty
}

func (d *testDeadliner) Add(duty core.Duty) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.added = append(d.added, duty)

	return true
}

func (d *testDeadliner) C() <-chan core.Duty {
	return d.ch
}

func (d *testDeadliner) expire() {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, duty := range d.added {
		d.ch <- duty
	}

	d.added = nil
}
