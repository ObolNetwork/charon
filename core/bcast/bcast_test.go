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

package bcast_test

import (
	"context"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/bcast"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestBroadcastAttestation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	mock := beaconmock.New()

	att := testutil.RandomAttestation()
	aggData, err := core.EncodeAttestationAggSignedData(att)
	require.NoError(t, err)

	// Assert output and cancel context
	mock.SubmitAttestationsFunc = func(ctx context.Context, attestations []*eth2p0.Attestation) error {
		require.Len(t, attestations, 1)
		require.Equal(t, att, attestations[0])
		cancel()

		return ctx.Err()
	}

	bcaster, err := bcast.New(mock)
	require.NoError(t, err)

	err = bcaster.Broadcast(ctx, core.Duty{Type: core.DutyAttester}, "", aggData)
	require.ErrorIs(t, err, context.Canceled)

	<-ctx.Done()
}
