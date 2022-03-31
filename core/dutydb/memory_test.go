// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dutydb_test

import (
	"context"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/dutydb"
	"github.com/obolnetwork/charon/testutil"
)

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
	unsignedA, err := core.EncodeAttesterUnsignedData(&core.AttestationData{
		Data: attData,
		Duty: eth2v1.AttesterDuty{
			CommitteeLength:         commLen,
			ValidatorCommitteeIndex: valCommIdxA,
			CommitteesAtSlot:        notZero,
		},
	})
	require.NoError(t, err)
	unsignedB, err := core.EncodeAttesterUnsignedData(&core.AttestationData{
		Data: attData,
		Duty: eth2v1.AttesterDuty{
			CommitteeLength:         commLen,
			ValidatorCommitteeIndex: valCommIdxB,
			CommitteesAtSlot:        notZero,
		},
	})
	require.NoError(t, err)

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
		block  *spec.VersionedBeaconBlock
		pubkey core.PubKey
	}
	awaitResponse := make(chan response)
	for i := 0; i < queries; i++ {
		go func(slot int) {
			pubkey, block, err := db.AwaitBeaconBlock(ctx, slots[slot])
			require.NoError(t, err)
			awaitResponse <- response{block: block, pubkey: pubkey}
		}(i)
	}

	blocks := make([]*spec.VersionedBeaconBlock, queries)
	pubkeysByIdx := make(map[eth2p0.ValidatorIndex]core.PubKey)
	for i := 0; i < queries; i++ {
		blocks[i] = &spec.VersionedBeaconBlock{
			Version: spec.DataVersionPhase0,
			Phase0: &eth2p0.BeaconBlock{
				Slot:          eth2p0.Slot(slots[i]),
				ProposerIndex: eth2p0.ValidatorIndex(i),
				ParentRoot:    testutil.RandomRoot(),
				StateRoot:     testutil.RandomRoot(),
				Body:          testutil.RandomBeaconBlockBody(),
			},
		}
		pubkeysByIdx[eth2p0.ValidatorIndex(i)] = testutil.RandomCorePubKey(t)
	}

	// Store the Blocks
	for i := 0; i < queries; i++ {
		unsigned, err := core.EncodeProposerUnsignedData(blocks[i])
		require.NoError(t, err)

		duty := core.Duty{Slot: slots[i], Type: core.DutyProposer}
		err = db.Store(ctx, duty, core.UnsignedDataSet{
			pubkeysByIdx[eth2p0.ValidatorIndex(i)]: unsigned,
		})
		require.NoError(t, err)
	}

	// Get and assert the proQuery responses
	for i := 0; i < queries; i++ {
		actualData := <-awaitResponse
		require.Equal(t, blocks[i], actualData.block)
		require.Equal(t, pubkeysByIdx[eth2p0.ValidatorIndex(i)], actualData.pubkey)
	}
}
