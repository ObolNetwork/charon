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

package leadercast_test

import (
	"bytes"
	"context"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/leadercast"
	"github.com/obolnetwork/charon/testutil"
)

func TestMemTransport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	trFunc := leadercast.NewMemTransportFunc(ctx)

	const (
		notZero = 99
		n       = 3
		vIdxA   = 0
		vIdxB   = 1
		vIdxC   = 2
		slots   = 3
		commIdx = 123
		commLen = 8
	)

	pubkeysByIdx := map[eth2p0.ValidatorIndex]core.PubKey{
		vIdxA: testutil.RandomPubKey(t),
		vIdxB: testutil.RandomPubKey(t),
		vIdxC: testutil.RandomPubKey(t),
	}

	var casts []*leadercast.LeaderCast
	for i := 0; i < n; i++ {
		c := leadercast.New(trFunc(), i, n)
		casts = append(casts, c)

		go func() {
			require.NoError(t, c.Run(ctx))
		}()
	}

	var expected []core.UnsignedDataSet
	resolved := make(chan core.UnsignedDataSet, slots*n)
	for i := 0; i < slots; i++ {
		duty := core.Duty{Slot: int64(i)}
		data := core.UnsignedDataSet{}
		for j := 0; j < n; j++ {
			unsignedData, err := core.EncodeAttesterUnsignedData(&core.AttestationData{
				Data: eth2p0.AttestationData{
					Slot:   eth2p0.Slot(i),
					Index:  commIdx,
					Source: &eth2p0.Checkpoint{},
					Target: &eth2p0.Checkpoint{},
				},
				Duty: eth2v1.AttesterDuty{
					CommitteeLength:         commLen,
					ValidatorCommitteeIndex: uint64(j),
					CommitteesAtSlot:        notZero,
				},
			})
			require.NoError(t, err)

			data[pubkeysByIdx[eth2p0.ValidatorIndex(j)]] = unsignedData
		}

		expected = append(expected, data)

		for j := 0; j < n; j++ {
			go func(node int) {
				err := casts[node].Propose(ctx, duty, data)
				require.NoError(t, err)
				resolved <- data
			}(j)
		}
	}

	var actual []core.UnsignedDataSet
	for i := 0; i < slots*n; i++ {
		actual = append(actual, <-resolved)
	}

	for _, expect := range expected {
		var count int
		for _, resolved := range actual {
			for j := 0; j < n; j++ {
				a := resolved[pubkeysByIdx[eth2p0.ValidatorIndex(j)]]
				b := expect[pubkeysByIdx[eth2p0.ValidatorIndex(j)]]
				if bytes.Equal(a, b) {
					count++
				}
			}
		}
		require.Equal(t, n*slots, count, expect)
	}
}
