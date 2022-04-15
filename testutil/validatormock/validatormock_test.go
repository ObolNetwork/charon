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

package validatormock_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
	"github.com/obolnetwork/charon/testutil/validatormock"
)

//go:generate go test -run=TestAttest -update -clean

func TestAttest(t *testing.T) {
	tests := []struct {
		DutyFactor int
		Expect     int
	}{
		{
			DutyFactor: 0, // All validators in first slot of epoch
			Expect:     3,
		},
		{
			DutyFactor: 1, // Validators spread over 1st, 2nd, 3rd slots of epoch
			Expect:     1,
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprint(test.DutyFactor), func(t *testing.T) {
			ctx := context.Background()
			clock := clockwork.NewFakeClockAt(time.Date(2022, 0o3, 20, 0o1, 0, 0, 0, time.UTC))

			// Configure beacon mock
			valSet := beaconmock.ValidatorSetA
			beaconMock, err := beaconmock.New(
				beaconmock.WithClock(clock),
				beaconmock.WithValidatorSet(valSet),
				beaconmock.WithDeterministicAttesterDuties(test.DutyFactor),
			)
			require.NoError(t, err)

			// Callback to collect attestations
			var atts []*eth2p0.Attestation
			beaconMock.SubmitAttestationsFunc = func(_ context.Context, attestations []*eth2p0.Attestation) error {
				atts = attestations
				return nil
			}

			// Signature stub function
			signFunc := func(ctx context.Context, key eth2p0.BLSPubKey, _ eth2p0.SigningData) (eth2p0.BLSSignature, error) {
				var sig eth2p0.BLSSignature
				copy(sig[:], key[:])

				return sig, nil
			}

			// Get first slot in epoch 1
			slotsPerEpoch, err := beaconMock.SlotsPerEpoch(ctx)
			require.NoError(t, err)

			// Call attest function
			err = validatormock.Attest(ctx,
				beaconMock, signFunc,
				eth2p0.Slot(slotsPerEpoch),
				valSet.PublicKeys()...,
			)
			require.NoError(t, err)

			// Assert length and expected attestations
			require.Len(t, atts, test.Expect)
			testutil.RequireGoldenJSON(t, atts)
		})
	}
}
