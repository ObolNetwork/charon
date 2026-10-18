// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatormock_test

import (
	"context"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
	"github.com/obolnetwork/charon/testutil/validatormock"
)

func TestBuilderPreferences(t *testing.T) {
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

	sig := testutil.RandomEth2Signature()
	signFunc := func(key eth2p0.BLSPubKey, _ []byte) (eth2p0.BLSSignature, error) { //nolint:unparam // The SignFunc signature requires an error.
		require.Equal(t, dutyPubkey, key)
		return sig, nil
	}

	newMock := func(t *testing.T) beaconmock.Mock {
		t.Helper()

		bmock, err := beaconmock.New(t.Context(), beaconmock.WithValidatorSet(valSet))
		require.NoError(t, err)

		bmock.ProposerDutiesV2Func = func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
			return []*eth2v1.ProposerDuty{{
				PubKey:         dutyPubkey,
				Slot:           slot,
				ValidatorIndex: dutyIdx,
			}}, nil
		}

		return bmock
	}

	urls := []string{"https://Relay-A.example.com:443/", "https://relay-b.example.com"}

	t.Run("submits an auth per builder", func(t *testing.T) {
		bmock := newMock(t)

		var submitted []*gloas.BuilderPreferencesEntry

		bmock.SubmitBuilderPreferencesFunc = func(_ context.Context, opts *eth2api.SubmitBuilderPreferencesOpts) error {
			submitted = opts.Preferences
			return nil
		}

		require.NoError(t, validatormock.BuilderPreferences(t.Context(), bmock, signFunc, slot, urls))
		require.Len(t, submitted, 2)

		for i, entry := range submitted {
			require.Equal(t, dutyPubkey, entry.ProposerPubkey)
			require.Equal(t, []byte(urls[i]), entry.URL)
			require.Equal(t, eth2p0.Slot(slot), entry.Auth.Message.Slot)
			require.Equal(t, sig, entry.Auth.Signature)
			require.NotZero(t, entry.MaxExecutionPayment)
		}

		// The auth data is the builder's hostname, as the validator clients derive it.
		require.Equal(t, []byte("relay-a.example.com"), submitted[0].Auth.Message.Data)
		require.Equal(t, []byte("relay-b.example.com"), submitted[1].Auth.Message.Data)
	})

	t.Run("no duty for slot", func(t *testing.T) {
		bmock := newMock(t)
		bmock.SubmitBuilderPreferencesFunc = func(context.Context, *eth2api.SubmitBuilderPreferencesOpts) error {
			require.Fail(t, "unexpected submission")
			return nil
		}

		require.NoError(t, validatormock.BuilderPreferences(t.Context(), bmock, signFunc, slot+1, urls))
	})

	t.Run("no builders", func(t *testing.T) {
		bmock := newMock(t)
		bmock.SubmitBuilderPreferencesFunc = func(context.Context, *eth2api.SubmitBuilderPreferencesOpts) error {
			require.Fail(t, "unexpected submission")
			return nil
		}

		require.NoError(t, validatormock.BuilderPreferences(t.Context(), bmock, signFunc, slot, nil))
	})
}
