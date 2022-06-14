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
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/dutydb"
	"github.com/obolnetwork/charon/testutil"
)

func TestShutdown(t *testing.T) {
	db := dutydb.NewMemDB()

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
	db := dutydb.NewMemDB()

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
	db := dutydb.NewMemDB()

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
	db := dutydb.NewMemDB()

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
	db := dutydb.NewMemDB()

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
	log.Error(ctx, "", err)
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
