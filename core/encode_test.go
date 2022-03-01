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

package core_test

import (
	"crypto/rand"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
)

func TestEncodeAttesterFetchArg(t *testing.T) {
	attDuty1 := &eth2v1.AttesterDuty{
		PubKey:                  randomPubKey(),
		Slot:                    1,
		ValidatorIndex:          2,
		CommitteeIndex:          3,
		CommitteeLength:         4,
		CommitteesAtSlot:        5,
		ValidatorCommitteeIndex: 6,
	}

	arg1, err := core.EncodeAttesterFetchArg(attDuty1)
	require.NoError(t, err)

	attDuty2, err := core.DecodeAttesterFetchArg(arg1)
	require.NoError(t, err)

	arg2, err := core.EncodeAttesterFetchArg(attDuty2)
	require.NoError(t, err)

	require.Equal(t, attDuty1, attDuty2)
	require.Equal(t, arg1, arg2)
}

func TestEncodeAttesterUnsignedData(t *testing.T) {
	attData1 := &eth2p0.AttestationData{
		Slot:            1,
		Index:           2,
		BeaconBlockRoot: randomRoot(),
		Source: &eth2p0.Checkpoint{
			Epoch: 3,
			Root:  randomRoot(),
		},
		Target: &eth2p0.Checkpoint{
			Epoch: 4,
			Root:  randomRoot(),
		},
	}

	data1, err := core.EncodeAttesterUnsingedData(attData1)
	require.NoError(t, err)

	attData2, err := core.DecodeAttesterUnsingedData(data1)
	require.NoError(t, err)

	data2, err := core.EncodeAttesterUnsingedData(attData1)
	require.NoError(t, err)

	require.Equal(t, attData1, attData2)
	require.Equal(t, data1, data2)
}

func randomRoot() eth2p0.Root {
	var root eth2p0.Root
	_, _ = rand.Read(root[:])

	return root
}

func randomPubKey() eth2p0.BLSPubKey {
	var pubkey eth2p0.BLSPubKey
	_, _ = rand.Read(pubkey[:])

	return pubkey
}
