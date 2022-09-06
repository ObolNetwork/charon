// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package dutydb_test

import (
	"context"
	"runtime"
	"sync"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/dutydb"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/testutil"
)

func TestShutdown(t *testing.T) {
	db := dutydb.NewMemDB(new(testDeadliner))

	errChan := make(chan error, 1)
	go func() {
		_, err := db.AwaitBeaconBlock(context.Background(), 999)
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
	pkA, err := db.PubKeyByAttestation(ctx, int64(attData.Slot), int64(attData.Index), valCommIdxA)
	require.NoError(t, err)
	require.Equal(t, pubkeysByIdx[vIdxA], pkA)

	pkB, err := db.PubKeyByAttestation(ctx, int64(attData.Slot), int64(attData.Index), valCommIdxB)
	require.NoError(t, err)
	require.Equal(t, pubkeysByIdx[vIdxB], pkB)
}

func TestMemDBProposer(t *testing.T) {
	ctx := context.Background()
	db := dutydb.NewMemDB(new(testDeadliner))

	const queries = 3
	slots := [queries]int64{123, 456, 789}

	type response struct {
		block *spec.VersionedBeaconBlock
	}
	var awaitResponse [queries]chan response
	for i := 0; i < queries; i++ {
		awaitResponse[i] = make(chan response)
		go func(slot int) {
			block, err := db.AwaitBeaconBlock(ctx, slots[slot])
			require.NoError(t, err)
			awaitResponse[slot] <- response{block: block}
		}(i)
	}

	blocks := make([]*spec.VersionedBeaconBlock, queries)
	pubkeysByIdx := make(map[eth2p0.ValidatorIndex]core.PubKey)
	for i := 0; i < queries; i++ {
		blocks[i] = &spec.VersionedBeaconBlock{
			Version: spec.DataVersionPhase0,
			Phase0:  testutil.RandomPhase0BeaconBlock(),
		}
		blocks[i].Phase0.Slot = eth2p0.Slot(slots[i])
		blocks[i].Phase0.ProposerIndex = eth2p0.ValidatorIndex(i)
		pubkeysByIdx[eth2p0.ValidatorIndex(i)] = testutil.RandomCorePubKey(t)
	}

	// Store the Blocks
	for i := 0; i < queries; i++ {
		unsigned, err := core.NewVersionedBeaconBlock(blocks[i])
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
		require.Equal(t, blocks[i], actualData.block)
	}
}

func TestMemDBClashingBlocks(t *testing.T) {
	ctx := context.Background()
	db := dutydb.NewMemDB(new(testDeadliner))

	const slot = 123
	block1 := &spec.VersionedBeaconBlock{
		Version: spec.DataVersionPhase0,
		Phase0:  testutil.RandomPhase0BeaconBlock(),
	}
	block1.Phase0.Slot = eth2p0.Slot(slot)
	block2 := &spec.VersionedBeaconBlock{
		Version: spec.DataVersionPhase0,
		Phase0:  testutil.RandomPhase0BeaconBlock(),
	}
	block2.Phase0.Slot = eth2p0.Slot(slot)
	pubkey := testutil.RandomCorePubKey(t)

	// Encode the Blocks
	unsigned1, err := core.NewVersionedBeaconBlock(block1)
	require.NoError(t, err)

	unsigned2, err := core.NewVersionedBeaconBlock(block2)
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

func TestMemDBClashProposer(t *testing.T) {
	ctx := context.Background()
	db := dutydb.NewMemDB(new(testDeadliner))

	const slot = 123

	block := &spec.VersionedBeaconBlock{
		Version: spec.DataVersionPhase0,
		Phase0:  testutil.RandomPhase0BeaconBlock(),
	}
	block.Phase0.Slot = eth2p0.Slot(slot)
	pubkey := testutil.RandomCorePubKey(t)

	// Encode the block
	unsigned, err := core.NewVersionedBeaconBlock(block)
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
	block.Phase0.ProposerIndex++
	unsignedB, err := core.NewVersionedBeaconBlock(block)
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
	slots := [queries]int64{123, 456, 789}

	type response struct {
		block *eth2api.VersionedBlindedBeaconBlock
	}
	var awaitResponse [queries]chan response
	for i := 0; i < queries; i++ {
		awaitResponse[i] = make(chan response)
		go func(slot int) {
			block, err := db.AwaitBlindedBeaconBlock(ctx, slots[slot])
			require.NoError(t, err)
			awaitResponse[slot] <- response{block: block}
		}(i)
	}

	blocks := make([]*eth2api.VersionedBlindedBeaconBlock, queries)
	pubkeysByIdx := make(map[eth2p0.ValidatorIndex]core.PubKey)
	for i := 0; i < queries; i++ {
		blocks[i] = &eth2api.VersionedBlindedBeaconBlock{
			Version:   spec.DataVersionBellatrix,
			Bellatrix: testutil.RandomBellatrixBlindedBeaconBlock(t),
		}
		blocks[i].Bellatrix.Slot = eth2p0.Slot(slots[i])
		blocks[i].Bellatrix.ProposerIndex = eth2p0.ValidatorIndex(i)
		pubkeysByIdx[eth2p0.ValidatorIndex(i)] = testutil.RandomCorePubKey(t)
	}

	// Store the Blocks
	for i := 0; i < queries; i++ {
		unsigned, err := core.NewVersionedBlindedBeaconBlock(blocks[i])
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
	block1 := &eth2api.VersionedBlindedBeaconBlock{
		Version:   spec.DataVersionBellatrix,
		Bellatrix: testutil.RandomBellatrixBlindedBeaconBlock(t),
	}
	block1.Bellatrix.Slot = eth2p0.Slot(slot)
	block2 := &eth2api.VersionedBlindedBeaconBlock{
		Version:   spec.DataVersionBellatrix,
		Bellatrix: testutil.RandomBellatrixBlindedBeaconBlock(t),
	}
	block2.Bellatrix.Slot = eth2p0.Slot(slot)
	pubkey := testutil.RandomCorePubKey(t)

	// Encode the Blocks
	unsigned1, err := core.NewVersionedBlindedBeaconBlock(block1)
	require.NoError(t, err)

	unsigned2, err := core.NewVersionedBlindedBeaconBlock(block2)
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

	block := &eth2api.VersionedBlindedBeaconBlock{
		Version:   spec.DataVersionBellatrix,
		Bellatrix: testutil.RandomBellatrixBlindedBeaconBlock(t),
	}
	block.Bellatrix.Slot = eth2p0.Slot(slot)
	pubkey := testutil.RandomCorePubKey(t)

	// Encode the block
	unsigned, err := core.NewVersionedBlindedBeaconBlock(block)
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
	unsignedB, err := core.NewVersionedBlindedBeaconBlock(block)
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
	const slot = int64(123)
	att1 := testutil.RandomCoreAttestationData(t)
	att1.Duty.Slot = eth2p0.Slot(slot)
	err := db.Store(ctx, core.NewAttesterDuty(slot), core.UnsignedDataSet{
		testutil.RandomCorePubKey(t): att1,
	})
	require.NoError(t, err)

	// Ensure it exists
	pk, err := db.PubKeyByAttestation(ctx, int64(att1.Data.Slot), int64(att1.Data.Index), int64(att1.Duty.ValidatorCommitteeIndex))
	require.NoError(t, err)
	require.NotEmpty(t, pk)

	// Expire attestation
	deadliner.expire()

	// Store another duty which deletes expired duties
	err = db.Store(ctx, core.NewProposerDuty(slot+1), core.UnsignedDataSet{
		testutil.RandomCorePubKey(t): testutil.RandomCoreVersionBeaconBlock(t),
	})
	require.NoError(t, err)

	// Pubkey not found.
	_, err = db.PubKeyByAttestation(ctx, int64(att1.Data.Slot), int64(att1.Data.Index), int64(att1.Duty.ValidatorCommitteeIndex))
	require.Error(t, err)
}

func TestMemDBCommSubResponse(t *testing.T) {
	ctx := context.Background()
	db := dutydb.NewMemDB(new(testDeadliner))

	const queries = 3
	slots := [queries]int64{123, 456, 789}
	vIdxs := [queries]int64{1, 2, 3}

	type response struct {
		commSubRes *eth2exp.BeaconCommitteeSubscriptionResponse
	}
	var awaitResponse [queries]chan response
	for i := 0; i < queries; i++ {
		awaitResponse[i] = make(chan response)
		go func(slot int) {
			res, err := db.AwaitCommitteeSubscriptionResponse(ctx, slots[slot], vIdxs[slot])
			require.NoError(t, err)
			awaitResponse[slot] <- response{commSubRes: res}
		}(i)
	}

	data := make([]*eth2exp.BeaconCommitteeSubscriptionResponse, queries)
	pubkeysByIdx := make(map[eth2p0.ValidatorIndex]core.PubKey)
	for i := 0; i < queries; i++ {
		data[i] = &eth2exp.BeaconCommitteeSubscriptionResponse{
			ValidatorIndex: eth2p0.ValidatorIndex(vIdxs[i]),
			IsAggregator:   false,
		}
		pubkeysByIdx[eth2p0.ValidatorIndex(i)] = testutil.RandomCorePubKey(t)

		require.NoError(t, db.Store(ctx, core.NewPrepareAggregatorDuty(slots[i]), core.UnsignedDataSet{
			pubkeysByIdx[eth2p0.ValidatorIndex(vIdxs[i])]: core.BeaconCommitteeSubscriptionResponse{BeaconCommitteeSubscriptionResponse: *data[i]},
		}))
	}

	// Get and assert the responses
	for i := 0; i < queries; i++ {
		actualData := <-awaitResponse[i]
		require.Equal(t, data[i], actualData.commSubRes)
	}
}

func TestMemDBClashingCommSubResponse(t *testing.T) {
	ctx := context.Background()
	db := dutydb.NewMemDB(new(testDeadliner))

	const (
		slot = 123
		vIdx = 1
	)
	res1 := &eth2exp.BeaconCommitteeSubscriptionResponse{
		ValidatorIndex: vIdx,
		IsAggregator:   false,
	}
	res2 := &eth2exp.BeaconCommitteeSubscriptionResponse{
		ValidatorIndex: vIdx,
		IsAggregator:   true,
	}
	pubkey := testutil.RandomCorePubKey(t)

	// Store the responses
	duty := core.NewPrepareAggregatorDuty(slot)
	require.NoError(t, db.Store(ctx, duty, core.UnsignedDataSet{
		pubkey: core.BeaconCommitteeSubscriptionResponse{BeaconCommitteeSubscriptionResponse: *res1},
	}))

	require.ErrorContains(t, db.Store(ctx, duty, core.UnsignedDataSet{
		pubkey: core.BeaconCommitteeSubscriptionResponse{BeaconCommitteeSubscriptionResponse: *res2},
	}), "clashing committee subscription response")
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
