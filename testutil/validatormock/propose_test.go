// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatormock_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
	"github.com/obolnetwork/charon/testutil/validatormock"
)

//go:generate go test -run=TestAttest -update -clean

func TestAttest(t *testing.T) {
	tests := []struct {
		DutyFactor         int
		ExpectAttestations int
		ExpectAggregations int
	}{
		{
			DutyFactor:         0, // All validators in first slot of epoch
			ExpectAttestations: 3,
			ExpectAggregations: 3, // All validators are aggregators in first slot
		},
		{
			DutyFactor:         1, // Validators spread over 1st, 2nd, 3rd slots of epoch
			ExpectAttestations: 1,
			ExpectAggregations: 1, // 1st is aggregator in first slot
		},
	}
	for _, test := range tests {
		t.Run(strconv.Itoa(test.DutyFactor), func(t *testing.T) {
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
			var atts []*eth2spec.VersionedAttestation
			var aggs *eth2api.SubmitAggregateAttestationsOpts
			beaconMock.SubmitAttestationsFunc = func(_ context.Context, attestations *eth2api.SubmitAttestationsOpts) error {
				atts = attestations.Attestations
				return nil
			}
			beaconMock.SubmitAggregateAttestationsFunc = func(_ context.Context, aggAndProofs *eth2api.SubmitAggregateAttestationsOpts) error {
				aggs = aggAndProofs
				return nil
			}

			// Signature stub function
			signFunc := func(key eth2p0.BLSPubKey, _ []byte) (eth2p0.BLSSignature, error) {
				var sig eth2p0.BLSSignature
				copy(sig[:], key[:])

				return sig, nil
			}

			// Get first slot in epoch 1
			slotsPerEpoch, err := beaconMock.SlotsPerEpoch(ctx)
			require.NoError(t, err)

			attester := validatormock.NewSlotAttester(beaconMock, eth2p0.Slot(slotsPerEpoch), signFunc, valSet.PublicKeys())

			require.NoError(t, attester.Prepare(ctx))
			require.NoError(t, attester.Attest(ctx))
			ok, err := attester.Aggregate(ctx)
			require.NoError(t, err)
			require.Equal(t, test.ExpectAggregations > 0, ok)

			// Assert length and expected attestations
			require.Len(t, atts, test.ExpectAttestations)
			require.Len(t, aggs, test.ExpectAggregations)

			// Sort the outputs to make it deterministic to compare with json.
			sort.Slice(atts, func(i, j int) bool {
				attsiData, err := atts[i].Data()
				if err != nil {
					return false
				}
				attsjData, err := atts[j].Data()
				if err != nil {
					return false
				}

				return attsiData.Index < attsjData.Index
			})

			sort.Slice(aggs.SignedAggregateAndProofs, func(i, j int) bool {
				return aggs.SignedAggregateAndProofs[i].Deneb.Message.Aggregate.Data.Index < aggs.SignedAggregateAndProofs[j].Deneb.Message.Aggregate.Data.Index
			})

			t.Run("attestations", func(t *testing.T) {
				testutil.RequireGoldenJSON(t, atts)
			})
			t.Run("aggregations", func(t *testing.T) {
				testutil.RequireGoldenJSON(t, aggs)
			})
		})
	}
}

func TestProposeBlock(t *testing.T) {
	ctx := context.Background()

	// Configure beacon mock
	valSet := beaconmock.ValidatorSetA
	beaconMock, err := beaconmock.New(
		beaconmock.WithValidatorSet(valSet),
		beaconmock.WithDeterministicProposerDuties(0),
	)
	require.NoError(t, err)

	// Signature stub function
	signFunc := func(key eth2p0.BLSPubKey, _ []byte) (eth2p0.BLSSignature, error) {
		var sig eth2p0.BLSSignature
		copy(sig[:], key[:])

		return sig, nil
	}

	slotsPerEpoch, err := beaconMock.SlotsPerEpoch(ctx)
	require.NoError(t, err)

	block := testutil.RandomPhase0BeaconBlock()
	block.Slot = eth2p0.Slot(slotsPerEpoch)

	mockVAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testResponse := []byte(`{"version":"phase0","data":`)
		blockJSON, err := block.MarshalJSON()
		require.NoError(t, err)

		testResponse = append(testResponse, blockJSON...)
		testResponse = append(testResponse, []byte(`}`)...)
		require.NoError(t, err)

		_, _ = w.Write(testResponse)
	}))
	defer mockVAPI.Close()

	provider := addrWrap{
		Client: beaconMock,
		addr:   mockVAPI.URL,
	}

	// Call propose block function
	err = validatormock.ProposeBlock(ctx, provider, signFunc, eth2p0.Slot(slotsPerEpoch))
	require.NoError(t, err)
}

func TestProposeBlindedBlock(t *testing.T) {
	ctx := context.Background()

	// Configure beacon mock
	valSet := beaconmock.ValidatorSetA
	beaconMock, err := beaconmock.New(
		beaconmock.WithValidatorSet(valSet),
		beaconmock.WithDeterministicProposerDuties(0),
	)
	require.NoError(t, err)

	// Signature stub function
	signFunc := func(key eth2p0.BLSPubKey, _ []byte) (eth2p0.BLSSignature, error) {
		var sig eth2p0.BLSSignature
		copy(sig[:], key[:])

		return sig, nil
	}

	slotsPerEpoch, err := beaconMock.SlotsPerEpoch(ctx)
	require.NoError(t, err)

	block := testutil.RandomBellatrixBlindedBeaconBlock()
	block.Slot = eth2p0.Slot(slotsPerEpoch)

	mockVAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testResponse := []byte(`{"version":"bellatrix","data":`)
		blockJSON, err := block.MarshalJSON()
		require.NoError(t, err)

		testResponse = append(testResponse, blockJSON...)
		testResponse = append(testResponse, []byte(`}`)...)
		require.NoError(t, err)

		w.Header().Set("Eth-Execution-Payload-Blinded", "true")

		_, _ = w.Write(testResponse)
	}))
	defer mockVAPI.Close()

	provider := addrWrap{
		Client: beaconMock,
		addr:   mockVAPI.URL,
	}

	// Call propose block function
	err = validatormock.ProposeBlock(ctx, provider, signFunc, eth2p0.Slot(slotsPerEpoch))
	require.NoError(t, err)
}

type addrWrap struct {
	eth2wrap.Client
	addr string
}

func (w addrWrap) Address() string {
	return w.addr
}
