package validatormock_test

import (
	"context"
	"fmt"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
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

			// Configure beacon mock
			static, err := beaconmock.NewStaticProvider(ctx)
			require.NoError(t, err)

			valSet := beaconmock.ValidatorSetA
			beaconMock := beaconmock.New(
				beaconmock.WithStaticProvider(static),
				beaconmock.WithValidatorSet(valSet),
				beaconmock.WithDeterministicDuties(test.DutyFactor),
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
			slotsPerEpoch, err := static.SlotsPerEpoch(ctx)
			require.NoError(t, err)

			// Call attest function
			err = validatormock.Attest(ctx,
				beaconMock, signFunc,
				eth2p0.Slot(slotsPerEpoch),
				valSet.ETH2PubKeys(),
			)
			require.NoError(t, err)

			// Assert length and expected attestations
			require.Len(t, atts, test.Expect)
			testutil.RequireGoldenJSON(t, atts)
		})
	}
}
