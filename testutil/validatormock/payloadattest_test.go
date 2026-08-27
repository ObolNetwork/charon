// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatormock_test

import (
	"context"
	"testing"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
	"github.com/obolnetwork/charon/testutil/validatormock"
)

func TestPayloadAttest(t *testing.T) {
	const slot = 123

	valSet := beaconmock.ValidatorSetA

	var (
		dutyIdx    eth2p0.ValidatorIndex
		dutyPubkey eth2p0.BLSPubKey
	)

	for idx, val := range valSet {
		dutyIdx = idx
		dutyPubkey = val.Validator.PublicKey

		break
	}

	attData := testutil.RandomVersionedPayloadAttestationData()
	attData.Gloas.Slot = slot

	sig := testutil.RandomEth2Signature()
	signFunc := func(key eth2p0.BLSPubKey, _ []byte) (eth2p0.BLSSignature, error) { //nolint:unparam // The SignFunc signature requires an error.
		require.Equal(t, dutyPubkey, key)
		return sig, nil
	}

	newMock := func(t *testing.T) beaconmock.Mock {
		t.Helper()

		bmock, err := beaconmock.New(t.Context(), beaconmock.WithValidatorSet(valSet))
		require.NoError(t, err)

		bmock.PTCDutiesFunc = func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.PTCDuty, error) {
			return []*eth2v1.PTCDuty{{
				PubKey:         dutyPubkey,
				Slot:           slot,
				ValidatorIndex: dutyIdx,
			}}, nil
		}
		bmock.PayloadAttestationDataFunc = func(context.Context, eth2p0.Slot) (*eth2spec.VersionedPayloadAttestationData, error) {
			return attData, nil
		}

		return bmock
	}

	t.Run("submit message", func(t *testing.T) {
		bmock := newMock(t)

		var submitted *eth2api.SubmitPayloadAttestationMessagesOpts

		bmock.SubmitPayloadAttestationMessagesFunc = func(_ context.Context, opts *eth2api.SubmitPayloadAttestationMessagesOpts) error {
			submitted = opts
			return nil
		}

		require.NoError(t, validatormock.PayloadAttest(t.Context(), bmock, signFunc, slot))
		require.NotNil(t, submitted)
		require.Len(t, submitted.Messages, 1)

		msg := submitted.Messages[0]
		require.Equal(t, eth2spec.DataVersionGloas, msg.Version)
		require.Equal(t, dutyIdx, msg.Gloas.ValidatorIndex)
		require.Equal(t, attData.Gloas, msg.Gloas.Data)
		require.Equal(t, sig, msg.Gloas.Signature)
	})

	t.Run("no duty for slot", func(t *testing.T) {
		bmock := newMock(t)
		bmock.SubmitPayloadAttestationMessagesFunc = func(context.Context, *eth2api.SubmitPayloadAttestationMessagesOpts) error {
			require.Fail(t, "unexpected submission")
			return nil
		}

		require.NoError(t, validatormock.PayloadAttest(t.Context(), bmock, signFunc, slot+1))
	})

	t.Run("no block seen", func(t *testing.T) {
		bmock := newMock(t)
		bmock.PayloadAttestationDataFunc = func(context.Context, eth2p0.Slot) (*eth2spec.VersionedPayloadAttestationData, error) {
			return nil, eth2client.ErrNoPayloadAttestationData
		}
		bmock.SubmitPayloadAttestationMessagesFunc = func(context.Context, *eth2api.SubmitPayloadAttestationMessagesOpts) error {
			require.Fail(t, "unexpected submission")
			return nil
		}

		require.NoError(t, validatormock.PayloadAttest(t.Context(), bmock, signFunc, slot))
	})

	t.Run("unknown version", func(t *testing.T) {
		bmock := newMock(t)
		bmock.PayloadAttestationDataFunc = func(context.Context, eth2p0.Slot) (*eth2spec.VersionedPayloadAttestationData, error) {
			return &eth2spec.VersionedPayloadAttestationData{Version: eth2spec.DataVersionElectra}, nil
		}

		require.ErrorContains(t, validatormock.PayloadAttest(t.Context(), bmock, signFunc, slot),
			"unknown payload attestation data version")
	})
}
