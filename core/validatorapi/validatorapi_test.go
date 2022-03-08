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

package validatorapi_test

import (
	"context"
	"testing"

	"github.com/attestantio/go-eth2-client/mock"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/dB2510/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/validatorapi"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
	"github.com/obolnetwork/charon/testutil/validatormock"
)

func TestComponent_ValidSubmitAttestations(t *testing.T) {
	ctx := context.Background()
	eth2Svc, err := mock.New(ctx)
	require.NoError(t, err)

	const (
		slot        = 123
		commIdx     = 456
		vIdxA       = 1
		vIdxB       = 2
		valCommIdxA = vIdxA
		valCommIdxB = vIdxB
		commLen     = 8
	)

	pubkeysByIdx := map[eth2p0.ValidatorIndex]core.PubKey{
		vIdxA: testutil.RandomPubKey(t),
		vIdxB: testutil.RandomPubKey(t),
	}

	component, err := validatorapi.NewComponentInsecure(eth2Svc, 0)
	require.NoError(t, err)

	aggBitsA := bitfield.NewBitlist(commLen)
	aggBitsA.SetBitAt(valCommIdxA, true)

	attA := &eth2p0.Attestation{
		AggregationBits: aggBitsA,
		Data: &eth2p0.AttestationData{
			Slot:   slot,
			Index:  commIdx,
			Source: &eth2p0.Checkpoint{},
			Target: &eth2p0.Checkpoint{},
		},
		Signature: eth2p0.BLSSignature{},
	}

	aggBitsB := bitfield.NewBitlist(commLen)
	aggBitsB.SetBitAt(valCommIdxB, true)

	attB := &eth2p0.Attestation{
		AggregationBits: aggBitsB,
		Data: &eth2p0.AttestationData{
			Slot:   slot,
			Index:  commIdx,
			Source: &eth2p0.Checkpoint{},
			Target: &eth2p0.Checkpoint{},
		},
		Signature: eth2p0.BLSSignature{},
	}

	atts := []*eth2p0.Attestation{attA, attB}

	component.RegisterPubKeyByAttestation(func(ctx context.Context, slot, commIdx, valCommIdx int64) (core.PubKey, error) {
		return pubkeysByIdx[eth2p0.ValidatorIndex(valCommIdx)], nil
	})

	component.RegisterParSigDB(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Equal(t, core.DutyAttester, duty.Type)
		require.Equal(t, int64(slot), duty.Slot)

		parSignedDataA := set[pubkeysByIdx[vIdxA]]
		actAttA, err := core.DecodeAttestationParSignedData(parSignedDataA)
		require.NoError(t, err)
		require.Equal(t, attA, actAttA)

		parSignedDataB := set[pubkeysByIdx[vIdxB]]
		actAttB, err := core.DecodeAttestationParSignedData(parSignedDataB)
		require.NoError(t, err)
		require.Equal(t, attB, actAttB)

		return nil
	})

	err = component.SubmitAttestations(ctx, atts)
	require.NoError(t, err)
}

func TestComponent_InvalidSubmitAttestations(t *testing.T) {
	ctx := context.Background()
	eth2Svc, err := mock.New(ctx)
	require.NoError(t, err)

	const (
		slot       = 123
		commIdx    = 456
		vIdx       = 1
		valCommIdx = vIdx
		commLen    = 8
	)

	component, err := validatorapi.NewComponentInsecure(eth2Svc, vIdx)
	require.NoError(t, err)

	aggBits := bitfield.NewBitlist(commLen)
	aggBits.SetBitAt(valCommIdx, true)
	aggBits.SetBitAt(valCommIdx+1, true)

	att := &eth2p0.Attestation{
		AggregationBits: aggBits,
		Data: &eth2p0.AttestationData{
			Slot:   slot,
			Index:  commIdx,
			Source: &eth2p0.Checkpoint{},
			Target: &eth2p0.Checkpoint{},
		},
		Signature: eth2p0.BLSSignature{},
	}

	atts := []*eth2p0.Attestation{att}

	err = component.SubmitAttestations(ctx, atts)
	require.Error(t, err)
}

func TestSubmitAttestations_Verify(t *testing.T) {
	ctx := context.Background()

	// Create keys
	pubkey, secret, err := bls_sig.NewSigEth2().Keygen()
	require.NoError(t, err)

	// Configure validator
	const vIdx = 1
	validator := beaconmock.ValidatorSetA[vIdx]

	b, err := pubkey.MarshalBinary()
	require.NoError(t, err)
	copy(validator.Validator.PublicKey[:], b)
	corePubKey, err := core.PubKeyFromBytes(b)
	require.NoError(t, err)

	// Configure beacon mock
	static, err := beaconmock.NewStaticProvider(ctx)
	require.NoError(t, err)

	bmock := beaconmock.New(
		beaconmock.WithStaticProvider(static),
		beaconmock.WithValidatorSet(beaconmock.ValidatorSet{vIdx: validator}),
		beaconmock.WithDeterministicDuties(0), // All duties in first slot of epoch.
	)
	require.NoError(t, err)

	epochSlot, err := bmock.SlotsPerEpoch(ctx)
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, stubPubShare, 0)
	require.NoError(t, err)

	vapi.RegisterPubKeyByAttestation(func(ctx context.Context, slot, commIdx, valCommIdx int64) (core.PubKey, error) {
		require.EqualValues(t, slot, epochSlot)
		require.EqualValues(t, commIdx, 0)
		require.EqualValues(t, valCommIdx, 0)

		return corePubKey, nil
	})

	// Collect submitted partial signature.
	vapi.RegisterParSigDB(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Len(t, set, 1)
		_, err := core.DecodeAttestationParSignedData(set[corePubKey])
		require.NoError(t, err)

		return nil
	})

	// Configure beacon mock to call validator API for submissions
	bmock.SubmitAttestationsFunc = vapi.SubmitAttestations

	// Run attestation using validator mock
	err = validatormock.Attest(ctx, bmock, validatormock.NewSigner(secret), eth2p0.Slot(epochSlot), validator.Validator.PublicKey)
	require.NoError(t, err)
}

// stubPubShare is a stub PubShareFunc that just returns the public key itself.
func stubPubShare(pubkey core.PubKey, _ int) (*bls_sig.PublicKey, error) {
	b, err := pubkey.Bytes()
	if err != nil {
		return nil, err
	}

	pk := new(bls_sig.PublicKey)
	if err := pk.UnmarshalBinary(b); err != nil {
		return nil, errors.Wrap(err, "unmarshal pubkey")
	}

	return pk, nil
}
