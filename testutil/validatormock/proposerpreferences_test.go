// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatormock_test

import (
	"context"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
	"github.com/obolnetwork/charon/testutil/validatormock"
)

func TestProposerPreferences(t *testing.T) {
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

	t.Run("submit preferences", func(t *testing.T) {
		bmock := newMock(t)

		var submitted []*gloas.SignedProposerPreferences

		bmock.SubmitProposerPreferencesFunc = func(_ context.Context, prefs []*gloas.SignedProposerPreferences) error {
			submitted = prefs
			return nil
		}

		require.NoError(t, validatormock.ProposerPreferences(t.Context(), bmock, signFunc, slot))
		require.Len(t, submitted, 1)

		pref := submitted[0]
		require.Equal(t, eth2p0.Slot(slot), pref.Message.ProposalSlot)
		require.Equal(t, dutyIdx, pref.Message.ValidatorIndex)
		require.NotZero(t, pref.Message.FeeRecipient)
		require.NotZero(t, pref.Message.TargetGasLimit)
		require.Equal(t, sig, pref.Signature)
	})

	t.Run("no duty for slot", func(t *testing.T) {
		bmock := newMock(t)
		bmock.SubmitProposerPreferencesFunc = func(context.Context, []*gloas.SignedProposerPreferences) error {
			require.Fail(t, "unexpected submission")
			return nil
		}

		require.NoError(t, validatormock.ProposerPreferences(t.Context(), bmock, signFunc, slot+1))
	})
}
