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

package validatorapi_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/validatorapi"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
	"github.com/obolnetwork/charon/testutil/validatormock"
)

func TestComponent_ValidSubmitAttestations(t *testing.T) {
	ctx := context.Background()
	eth2Svc, err := beaconmock.New()
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
		vIdxA: testutil.RandomCorePubKey(t),
		vIdxB: testutil.RandomCorePubKey(t),
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

	component.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Equal(t, core.DutyAttester, duty.Type)
		require.Equal(t, int64(slot), duty.Slot)

		parSignedDataA := set[pubkeysByIdx[vIdxA]]
		actAttA, ok := parSignedDataA.SignedData.(core.Attestation)
		require.True(t, ok)
		require.Equal(t, *attA, actAttA.Attestation)

		parSignedDataB := set[pubkeysByIdx[vIdxB]]
		actAttB, ok := parSignedDataB.SignedData.(core.Attestation)
		require.True(t, ok)
		require.Equal(t, *attB, actAttB.Attestation)

		return nil
	})

	err = component.SubmitAttestations(ctx, atts)
	require.NoError(t, err)
}

func TestComponent_InvalidSubmitAttestations(t *testing.T) {
	ctx := context.Background()
	eth2Svc, err := beaconmock.New()
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

	// Create keys (just use normal keys, not split tbls)
	pubkey, secret, err := tbls.Keygen()
	require.NoError(t, err)

	// Configure validator
	const vIdx = 1

	validator := beaconmock.ValidatorSetA[vIdx]
	validator.Validator.PublicKey, err = tblsconv.KeyToETH2(pubkey)
	require.NoError(t, err)

	// Convert pubkey
	corePubKey, err := tblsconv.KeyToCore(pubkey)
	require.NoError(t, err)
	pubShareByKey := map[*bls_sig.PublicKey]*bls_sig.PublicKey{pubkey: pubkey} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New(
		beaconmock.WithValidatorSet(beaconmock.ValidatorSet{vIdx: validator}),
		beaconmock.WithDeterministicAttesterDuties(0), // All duties in first slot of epoch.
	)
	require.NoError(t, err)

	epochSlot, err := bmock.SlotsPerEpoch(ctx)
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, pubShareByKey, 0)
	require.NoError(t, err)

	vapi.RegisterPubKeyByAttestation(func(ctx context.Context, slot, commIdx, valCommIdx int64) (core.PubKey, error) {
		require.EqualValues(t, slot, epochSlot)
		require.EqualValues(t, commIdx, 0)
		require.EqualValues(t, valCommIdx, vIdx)

		return corePubKey, nil
	})

	// Collect submitted partial signature.
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Len(t, set, 1)
		_, ok := set[corePubKey]
		require.True(t, ok)

		return nil
	})

	// Configure beacon mock to call validator API for submissions
	bmock.SubmitAttestationsFunc = vapi.SubmitAttestations

	// Run attestation using validator mock
	err = validatormock.Attest(ctx, bmock, validatormock.NewSigner(secret), eth2p0.Slot(epochSlot), validator.Validator.PublicKey)
	require.NoError(t, err)
}

// TestSignAndVerify signs and verifies the signature.
// Test input and output obtained from prysm/validator/client/attest_test.go#TestSignAttestation.
func TestSignAndVerify(t *testing.T) {
	ctx := context.Background()

	// Create key pair
	secretKey, err := tblsconv.SecretFromBytes(padTo([]byte{1}, 32))
	require.NoError(t, err)

	// Setup beaconmock
	forkSchedule := `{"data": [{
        	"previous_version": "0x61626364",
			"current_version": "0x64656666",
        	"epoch": "0"
      	}]}`
	bmock, err := beaconmock.New(
		beaconmock.WithEndpoint("/eth/v1/config/fork_schedule", forkSchedule),
		beaconmock.WithGenesisValidatorsRoot([32]byte{0x01, 0x02}))
	require.NoError(t, err)

	// Get and assert domain
	domain, err := signing.GetDomain(ctx, bmock, signing.DomainBeaconAttester, 0)
	require.NoError(t, err)
	require.Equal(t, "0x0100000011b4296f38fa573d05f00854d452e120725b4d24b5587a472c6c4258", fmt.Sprintf("%#x", domain))

	// Define attestation data to sign
	blockRoot := padTo([]byte("blockRoot"), 32)
	var eth2Root eth2p0.Root
	copy(eth2Root[:], blockRoot)
	attData := eth2p0.AttestationData{
		Slot:            999,
		Index:           0,
		BeaconBlockRoot: eth2Root,
		Source:          &eth2p0.Checkpoint{Epoch: 100},
		Target:          &eth2p0.Checkpoint{Epoch: 200},
	}

	// Assert attestation data
	attRoot, err := attData.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, "0xeee68bd8e94662122695d04afa5fd5c30ae385c9f39d98aa840062f43221d0d0", fmt.Sprintf("%#x", attRoot))

	// Create and assert signing data
	sigData := eth2p0.SigningData{ObjectRoot: attRoot, Domain: domain}
	sigDataBytes, err := sigData.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, "0x02bbdb88056d6cbafd6e94575540e74b8cf2c0f2c1b79b8e17e7b21ed1694305", fmt.Sprintf("%#x", sigDataBytes))

	// Get pubkey
	pubkey, err := secretKey.GetPublicKey()
	require.NoError(t, err)
	eth2Pubkey, err := tblsconv.KeyToETH2(pubkey)
	require.NoError(t, err)

	// Sign
	sig, err := validatormock.NewSigner(secretKey)(ctx, eth2Pubkey, sigDataBytes[:])
	require.NoError(t, err)

	// Assert signature
	require.Equal(t, "0xb6a60f8497bd328908be83634d045dd7a32f5e246b2c4031fc2f316983f362e36fc27fd3d6d5a2b15b4dbff38804ffb10b1719b7ebc54e9cbf3293fd37082bc0fc91f79d70ce5b04ff13de3c8e10bb41305bfdbe921a43792c12624f225ee865",
		fmt.Sprintf("%#x", sig))

	// Setup validatorapi component.
	vapi, err := validatorapi.NewComponent(bmock, map[*bls_sig.PublicKey]*bls_sig.PublicKey{
		pubkey: pubkey,
	}, 0)
	require.NoError(t, err)
	vapi.RegisterPubKeyByAttestation(func(context.Context, int64, int64, int64) (core.PubKey, error) {
		return tblsconv.KeyToCore(pubkey)
	})

	// Assert output
	var wg sync.WaitGroup
	wg.Add(1)
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Equal(t, core.DutyAttester, duty.Type)
		require.Len(t, set, 1)
		wg.Done()

		return nil
	})

	// Create and submit attestation.
	aggBits := bitfield.NewBitlist(1)
	aggBits.SetBitAt(0, true)
	att := eth2p0.Attestation{
		AggregationBits: aggBits,
		Data:            &attData,
		Signature:       sig,
	}
	err = vapi.SubmitAttestations(ctx, []*eth2p0.Attestation{&att})
	require.NoError(t, err)
	wg.Wait()
}

// padTo pads a byte slice to the given size.
// It was copied from prysm/encoding/bytesutil/bytes.go.
func padTo(b []byte, size int) []byte {
	if len(b) > size {
		return b
	}

	return append(b, make([]byte, size-len(b))...)
}

func TestComponent_BeaconBlockProposal(t *testing.T) {
	ctx := context.Background()
	eth2Svc, err := beaconmock.New()
	require.NoError(t, err)

	const (
		slot = 123
		vIdx = 1
	)

	component, err := validatorapi.NewComponentInsecure(eth2Svc, vIdx)
	require.NoError(t, err)

	pk, secret, err := tbls.Keygen()
	require.NoError(t, err)

	msg := []byte("randao reveal")
	sig, err := tbls.Sign(secret, msg)
	require.NoError(t, err)

	randao := tblsconv.SigToETH2(sig)
	pubkey, err := tblsconv.KeyToCore(pk)
	require.NoError(t, err)

	block1 := &spec.VersionedBeaconBlock{
		Version: spec.DataVersionPhase0,
		Phase0:  testutil.RandomPhase0BeaconBlock(),
	}
	block1.Phase0.Slot = slot
	block1.Phase0.ProposerIndex = vIdx
	block1.Phase0.Body.RANDAOReveal = randao

	component.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{pubkey: nil}, nil
	})

	component.RegisterAwaitBeaconBlock(func(ctx context.Context, slot int64) (*spec.VersionedBeaconBlock, error) {
		return block1, nil
	})

	component.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Equal(t, set, core.ParSignedDataSet{
			pubkey: core.NewPartialSignature(core.SigFromETH2(randao), vIdx),
		})
		require.Equal(t, duty, core.NewRandaoDuty(slot))

		return nil
	})

	block2, err := component.BeaconBlockProposal(ctx, slot, randao, []byte{})
	require.NoError(t, err)
	require.Equal(t, block1, block2)
}

func TestComponent_SubmitBeaconBlock(t *testing.T) {
	ctx := context.Background()

	// Create keys (just use normal keys, not split tbls)
	pubkey, secret, err := tbls.Keygen()
	require.NoError(t, err)

	const (
		vIdx  = 1
		slot  = 123
		epoch = eth2p0.Epoch(3)
	)

	// Convert pubkey
	corePubKey, err := tblsconv.KeyToCore(pubkey)
	require.NoError(t, err)
	pubShareByKey := map[*bls_sig.PublicKey]*bls_sig.PublicKey{pubkey: pubkey} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, pubShareByKey, 0)
	require.NoError(t, err)

	// Prepare unsigned beacon block
	msg := []byte("randao reveal")
	sig, err := tbls.Sign(secret, msg)
	require.NoError(t, err)

	randao := tblsconv.SigToETH2(sig)
	unsignedBlock := &spec.VersionedBeaconBlock{
		Version: spec.DataVersionPhase0,
		Phase0:  testutil.RandomPhase0BeaconBlock(),
	}
	unsignedBlock.Phase0.Body.RANDAOReveal = randao
	unsignedBlock.Phase0.Slot = slot
	unsignedBlock.Phase0.ProposerIndex = vIdx

	vapi.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{corePubKey: nil}, nil
	})

	// Sign beacon block
	sigRoot, err := unsignedBlock.Root()
	require.NoError(t, err)

	domain, err := signing.GetDomain(ctx, bmock, signing.DomainBeaconProposer, epoch)
	require.NoError(t, err)

	sigData, err := (&eth2p0.SigningData{ObjectRoot: sigRoot, Domain: domain}).HashTreeRoot()
	require.NoError(t, err)

	s, err := tbls.Sign(secret, sigData[:])
	require.NoError(t, err)

	sigEth2 := tblsconv.SigToETH2(s)
	signedBlock := &spec.VersionedSignedBeaconBlock{
		Version: spec.DataVersionPhase0,
		Phase0: &eth2p0.SignedBeaconBlock{
			Message:   unsignedBlock.Phase0,
			Signature: sigEth2,
		},
	}

	// Register subscriber
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		block, ok := set[corePubKey].SignedData.(core.VersionedSignedBeaconBlock)
		require.True(t, ok)
		require.Equal(t, *signedBlock, block.VersionedSignedBeaconBlock)

		return nil
	})

	err = vapi.SubmitBeaconBlock(ctx, signedBlock)
	require.NoError(t, err)
}

func TestComponent_SubmitBeaconBlockInvalidSignature(t *testing.T) {
	ctx := context.Background()

	// Create keys (just use normal keys, not split tbls)
	pubkey, secret, err := tbls.Keygen()
	require.NoError(t, err)

	const (
		vIdx = 1
		slot = 123
	)

	// Convert pubkey
	corePubKey, err := tblsconv.KeyToCore(pubkey)
	require.NoError(t, err)
	pubShareByKey := map[*bls_sig.PublicKey]*bls_sig.PublicKey{pubkey: pubkey} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, pubShareByKey, 0)
	require.NoError(t, err)

	// Prepare unsigned beacon block
	msg := []byte("randao reveal")
	sig, err := tbls.Sign(secret, msg)
	require.NoError(t, err)

	randao := tblsconv.SigToETH2(sig)
	unsignedBlock := &spec.VersionedBeaconBlock{
		Version: spec.DataVersionPhase0,
		Phase0:  testutil.RandomPhase0BeaconBlock(),
	}
	unsignedBlock.Phase0.Body.RANDAOReveal = randao
	unsignedBlock.Phase0.Slot = slot
	unsignedBlock.Phase0.ProposerIndex = vIdx

	vapi.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{corePubKey: nil}, nil
	})

	// Add invalid Signature to beacon block

	s, err := tbls.Sign(secret, []byte("invalid msg"))
	require.NoError(t, err)

	sigEth2 := tblsconv.SigToETH2(s)
	signedBlock := &spec.VersionedSignedBeaconBlock{
		Version: spec.DataVersionPhase0,
		Phase0: &eth2p0.SignedBeaconBlock{
			Message:   unsignedBlock.Phase0,
			Signature: sigEth2,
		},
	}

	// Register subscriber
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		block, ok := set[corePubKey].SignedData.(core.VersionedSignedBeaconBlock)
		require.True(t, ok)
		require.Equal(t, signedBlock, block)

		return nil
	})

	err = vapi.SubmitBeaconBlock(ctx, signedBlock)
	require.ErrorContains(t, err, "invalid signature")
}

func TestComponent_SubmitBeaconBlockInvalidBlock(t *testing.T) {
	ctx := context.Background()

	// Create keys (just use normal keys, not split tbls)
	pubkey := testutil.RandomCorePubKey(t)

	// Convert pubkey
	pk, err := tblsconv.KeyFromCore(pubkey)
	require.NoError(t, err)
	pubShareByKey := map[*bls_sig.PublicKey]*bls_sig.PublicKey{pk: pk} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, pubShareByKey, 0)
	require.NoError(t, err)

	vapi.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{pubkey: nil}, nil
	})

	// invalid block scenarios
	tests := []struct {
		name   string
		block  *spec.VersionedSignedBeaconBlock
		errMsg string
	}{
		{
			name:   "no phase 0 block",
			block:  &spec.VersionedSignedBeaconBlock{Version: spec.DataVersionPhase0},
			errMsg: "no phase0 block",
		},
		{
			name:   "no altair block",
			block:  &spec.VersionedSignedBeaconBlock{Version: spec.DataVersionAltair},
			errMsg: "no altair block",
		},
		{
			name:   "no bellatrix block",
			block:  &spec.VersionedSignedBeaconBlock{Version: spec.DataVersionBellatrix},
			errMsg: "no bellatrix block",
		},
		{
			name:   "none",
			block:  &spec.VersionedSignedBeaconBlock{Version: spec.DataVersion(3)},
			errMsg: "unknown version",
		},
		{
			name: "no phase 0 sig",
			block: &spec.VersionedSignedBeaconBlock{
				Version: spec.DataVersionPhase0,
				Phase0: &eth2p0.SignedBeaconBlock{
					Message:   &eth2p0.BeaconBlock{Slot: eth2p0.Slot(123)},
					Signature: eth2p0.BLSSignature{},
				},
			},
			errMsg: "no phase0 signature",
		},
		{
			name: "no altair sig",
			block: &spec.VersionedSignedBeaconBlock{
				Version: spec.DataVersionAltair,
				Altair: &altair.SignedBeaconBlock{
					Message:   &altair.BeaconBlock{Slot: eth2p0.Slot(123)},
					Signature: eth2p0.BLSSignature{},
				},
			},
			errMsg: "no altair signature",
		},
		{
			name: "no bellatrix sig",
			block: &spec.VersionedSignedBeaconBlock{
				Version: spec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBeaconBlock{
					Message:   &bellatrix.BeaconBlock{Slot: eth2p0.Slot(123)},
					Signature: eth2p0.BLSSignature{},
				},
			},
			errMsg: "no bellatrix signature",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err = vapi.SubmitBeaconBlock(ctx, test.block)
			require.ErrorContains(t, err, test.errMsg)
		})
	}
}

func TestComponent_BlindedBeaconBlockProposal(t *testing.T) {
	ctx := context.Background()
	eth2Svc, err := beaconmock.New()
	require.NoError(t, err)

	const (
		slot = 123
		vIdx = 1
	)

	component, err := validatorapi.NewComponentInsecure(eth2Svc, vIdx)
	require.NoError(t, err)

	pk, secret, err := tbls.Keygen()
	require.NoError(t, err)

	msg := []byte("randao reveal")
	sig, err := tbls.Sign(secret, msg)
	require.NoError(t, err)

	randao := tblsconv.SigToETH2(sig)
	pubkey, err := tblsconv.KeyToCore(pk)
	require.NoError(t, err)

	block1 := &eth2api.VersionedBlindedBeaconBlock{
		Version:   spec.DataVersionPhase0,
		Bellatrix: testutil.RandomBellatrixBlindedBeaconBlock(t),
	}
	block1.Bellatrix.Slot = slot
	block1.Bellatrix.ProposerIndex = vIdx
	block1.Bellatrix.Body.RANDAOReveal = randao

	component.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{pubkey: nil}, nil
	})

	component.RegisterAwaitBlindedBeaconBlock(func(ctx context.Context, slot int64) (*eth2api.VersionedBlindedBeaconBlock, error) {
		return block1, nil
	})

	component.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Equal(t, set, core.ParSignedDataSet{
			pubkey: core.NewPartialSignature(core.SigFromETH2(randao), vIdx),
		})
		require.Equal(t, duty, core.NewRandaoDuty(slot))

		return nil
	})

	block2, err := component.BlindedBeaconBlockProposal(ctx, slot, randao, []byte{})
	require.NoError(t, err)
	require.Equal(t, block1, block2)
}

func TestComponent_SubmitBlindedBeaconBlock(t *testing.T) {
	ctx := context.Background()

	// Create keys (just use normal keys, not split tbls)
	pubkey, secret, err := tbls.Keygen()
	require.NoError(t, err)

	const (
		vIdx  = 1
		slot  = 123
		epoch = eth2p0.Epoch(3)
	)

	// Convert pubkey
	corePubKey, err := tblsconv.KeyToCore(pubkey)
	require.NoError(t, err)
	pubShareByKey := map[*bls_sig.PublicKey]*bls_sig.PublicKey{pubkey: pubkey} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, pubShareByKey, 0)
	require.NoError(t, err)

	// Prepare unsigned beacon block
	msg := []byte("randao reveal")
	sig, err := tbls.Sign(secret, msg)
	require.NoError(t, err)

	randao := tblsconv.SigToETH2(sig)
	unsignedBlindedBlock := &eth2api.VersionedBlindedBeaconBlock{
		Version:   spec.DataVersionBellatrix,
		Bellatrix: testutil.RandomBellatrixBlindedBeaconBlock(t),
	}
	unsignedBlindedBlock.Bellatrix.Body.RANDAOReveal = randao
	unsignedBlindedBlock.Bellatrix.Slot = slot
	unsignedBlindedBlock.Bellatrix.ProposerIndex = vIdx

	vapi.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{corePubKey: nil}, nil
	})

	// Sign blinded beacon block
	sigRoot, err := unsignedBlindedBlock.Root()
	require.NoError(t, err)

	domain, err := signing.GetDomain(ctx, bmock, signing.DomainBeaconProposer, epoch)
	require.NoError(t, err)

	sigData, err := (&eth2p0.SigningData{ObjectRoot: sigRoot, Domain: domain}).HashTreeRoot()
	require.NoError(t, err)

	s, err := tbls.Sign(secret, sigData[:])
	require.NoError(t, err)

	sigEth2 := tblsconv.SigToETH2(s)
	signedBlindedBlock := &eth2api.VersionedSignedBlindedBeaconBlock{
		Version: spec.DataVersionBellatrix,
		Bellatrix: &eth2v1.SignedBlindedBeaconBlock{
			Message:   unsignedBlindedBlock.Bellatrix,
			Signature: sigEth2,
		},
	}

	// Register subscriber
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		block, ok := set[corePubKey].SignedData.(core.VersionedSignedBlindedBeaconBlock)
		require.True(t, ok)
		require.Equal(t, *signedBlindedBlock, block.VersionedSignedBlindedBeaconBlock)

		return nil
	})

	err = vapi.SubmitBlindedBeaconBlock(ctx, signedBlindedBlock)
	require.NoError(t, err)
}

func TestComponent_SubmitBlindedBeaconBlockInvalidSignature(t *testing.T) {
	ctx := context.Background()

	// Create keys (just use normal keys, not split tbls)
	pubkey, secret, err := tbls.Keygen()
	require.NoError(t, err)

	const (
		vIdx = 1
		slot = 123
	)

	// Convert pubkey
	corePubKey, err := tblsconv.KeyToCore(pubkey)
	require.NoError(t, err)
	pubShareByKey := map[*bls_sig.PublicKey]*bls_sig.PublicKey{pubkey: pubkey} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, pubShareByKey, 0)
	require.NoError(t, err)

	// Prepare unsigned beacon block
	msg := []byte("randao reveal")
	sig, err := tbls.Sign(secret, msg)
	require.NoError(t, err)

	randao := tblsconv.SigToETH2(sig)
	unsignedBlindedBlock := &eth2api.VersionedBlindedBeaconBlock{
		Version:   spec.DataVersionPhase0,
		Bellatrix: testutil.RandomBellatrixBlindedBeaconBlock(t),
	}
	unsignedBlindedBlock.Bellatrix.Body.RANDAOReveal = randao
	unsignedBlindedBlock.Bellatrix.Slot = slot
	unsignedBlindedBlock.Bellatrix.ProposerIndex = vIdx

	vapi.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{corePubKey: nil}, nil
	})

	// Add invalid Signature to blinded beacon block

	s, err := tbls.Sign(secret, []byte("invalid msg"))
	require.NoError(t, err)

	sigEth2 := tblsconv.SigToETH2(s)
	signedBlindedBlock := &eth2api.VersionedSignedBlindedBeaconBlock{
		Version: spec.DataVersionBellatrix,
		Bellatrix: &eth2v1.SignedBlindedBeaconBlock{
			Message:   unsignedBlindedBlock.Bellatrix,
			Signature: sigEth2,
		},
	}

	// Register subscriber
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		block, ok := set[corePubKey].SignedData.(core.VersionedSignedBlindedBeaconBlock)
		require.True(t, ok)
		require.Equal(t, signedBlindedBlock, block)

		return nil
	})

	err = vapi.SubmitBlindedBeaconBlock(ctx, signedBlindedBlock)
	require.ErrorContains(t, err, "invalid signature")
}

func TestComponent_SubmitBlindedBeaconBlockInvalidBlock(t *testing.T) {
	ctx := context.Background()

	// Create keys (just use normal keys, not split tbls)
	pubkey := testutil.RandomCorePubKey(t)

	// Convert pubkey
	pk, err := tblsconv.KeyFromCore(pubkey)
	require.NoError(t, err)
	pubShareByKey := map[*bls_sig.PublicKey]*bls_sig.PublicKey{pk: pk} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, pubShareByKey, 0)
	require.NoError(t, err)

	vapi.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{pubkey: nil}, nil
	})

	// invalid block scenarios
	tests := []struct {
		name   string
		block  *eth2api.VersionedSignedBlindedBeaconBlock
		errMsg string
	}{
		{
			name:   "no bellatrix block",
			block:  &eth2api.VersionedSignedBlindedBeaconBlock{Version: spec.DataVersionBellatrix},
			errMsg: "no bellatrix block",
		},
		{
			name:   "none",
			block:  &eth2api.VersionedSignedBlindedBeaconBlock{Version: spec.DataVersion(3)},
			errMsg: "unsupported version",
		},
		{
			name: "no bellatrix sig",
			block: &eth2api.VersionedSignedBlindedBeaconBlock{
				Version: spec.DataVersionBellatrix,
				Bellatrix: &eth2v1.SignedBlindedBeaconBlock{
					Message:   &eth2v1.BlindedBeaconBlock{Slot: eth2p0.Slot(123)},
					Signature: eth2p0.BLSSignature{},
				},
			},
			errMsg: "no bellatrix signature",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err = vapi.SubmitBlindedBeaconBlock(ctx, test.block)
			require.ErrorContains(t, err, test.errMsg)
		})
	}
}

func TestComponent_SubmitVoluntaryExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create keys (just use normal keys, not split tbls)
	pubkey, secret, err := tbls.Keygen()
	require.NoError(t, err)

	const vIdx = 2
	const epoch = 10

	// Convert pubkey
	corePubKey, err := tblsconv.KeyToCore(pubkey)
	require.NoError(t, err)
	pubShareByKey := map[*bls_sig.PublicKey]*bls_sig.PublicKey{pubkey: pubkey} // Maps self to self since not tbls

	// Prep beacon mock validators
	validator := beaconmock.ValidatorSetA[vIdx]
	validator.Validator.PublicKey, err = tblsconv.KeyToETH2(pubkey)
	require.NoError(t, err)

	// Configure beacon mock
	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(beaconmock.ValidatorSetA))
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, pubShareByKey, 0)
	require.NoError(t, err)

	// Prepare unsigned voluntary exit
	exit := &eth2p0.VoluntaryExit{
		Epoch:          epoch,
		ValidatorIndex: vIdx,
	}

	// sign voluntary exit
	sigRoot, err := exit.HashTreeRoot()
	require.NoError(t, err)

	domain, err := signing.GetDomain(ctx, bmock, signing.DomainExit, epoch)
	require.NoError(t, err)

	sigData, err := (&eth2p0.SigningData{ObjectRoot: sigRoot, Domain: domain}).HashTreeRoot()
	require.NoError(t, err)

	sig, err := tbls.Sign(secret, sigData[:])
	require.NoError(t, err)

	signedExit := &eth2p0.SignedVoluntaryExit{
		Message:   exit,
		Signature: tblsconv.SigToETH2(sig),
	}

	// Register subscriber
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		signedExit2, ok := set[corePubKey].SignedData.(core.SignedVoluntaryExit)
		require.True(t, ok)
		require.Equal(t, *signedExit, signedExit2.SignedVoluntaryExit)
		cancel()

		return ctx.Err()
	})

	err = vapi.SubmitVoluntaryExit(ctx, signedExit)
	require.ErrorIs(t, err, context.Canceled)
}

func TestComponent_SubmitVoluntaryExitInvalidSignature(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create keys (just use normal keys, not split tbls)
	pubkey, secret, err := tbls.Keygen()
	require.NoError(t, err)

	const vIdx = 2

	pubShareByKey := map[*bls_sig.PublicKey]*bls_sig.PublicKey{pubkey: pubkey} // Maps self to self since not tbls

	validator := beaconmock.ValidatorSetA[vIdx]
	validator.Validator.PublicKey, err = tblsconv.KeyToETH2(pubkey)
	require.NoError(t, err)

	// Configure beacon mock
	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(beaconmock.ValidatorSetA))
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, pubShareByKey, 0)
	require.NoError(t, err)

	// Register subscriber
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		cancel()
		return ctx.Err()
	})

	sig, err := tbls.Sign(secret, []byte("invalid message"))
	require.NoError(t, err)

	exit := testutil.RandomExit()
	exit.Message.ValidatorIndex = vIdx
	exit.Signature = tblsconv.SigToETH2(sig)

	err = vapi.SubmitVoluntaryExit(ctx, exit)
	require.ErrorContains(t, err, "invalid signature")
}

func TestComponent_ProposerDuties(t *testing.T) {
	ctx := context.Background()

	// Configure validator
	const vIdx = 1

	tss, _, err := tbls.GenerateTSS(3, 4, rand.Reader)
	require.NoError(t, err)

	// Create keys (just use normal keys, not split tbls)
	pubkey := tss.PublicKey()
	pubshare := tss.PublicShare(vIdx)

	eth2Share, err := tblsconv.KeyToETH2(pubshare)
	require.NoError(t, err)

	validator := beaconmock.ValidatorSetA[vIdx]
	validator.Validator.PublicKey, err = tblsconv.KeyToETH2(pubkey)
	require.NoError(t, err)

	pubShareByKey := map[*bls_sig.PublicKey]*bls_sig.PublicKey{pubkey: pubshare} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New(
		beaconmock.WithValidatorSet(beaconmock.ValidatorSet{vIdx: validator}),
		beaconmock.WithDeterministicProposerDuties(0), // All duties in first slot of epoch.
	)
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, pubShareByKey, 0)
	require.NoError(t, err)

	duties, err := vapi.ProposerDuties(ctx, eth2p0.Epoch(0), []eth2p0.ValidatorIndex{eth2p0.ValidatorIndex(vIdx)})
	require.NoError(t, err)
	require.Len(t, duties, 1)
	require.Equal(t, duties[0].PubKey, eth2Share)
}

func TestComponent_SubmitValidatorRegistration(t *testing.T) {
	ctx := context.Background()

	// Create keys (just use normal keys, not split tbls)
	pubkey, secret, err := tbls.Keygen()
	require.NoError(t, err)

	// Convert pubkey
	eth2Pubkey, err := tblsconv.KeyToETH2(pubkey)
	require.NoError(t, err)
	corePubKey, err := tblsconv.KeyToCore(pubkey)
	require.NoError(t, err)
	pubShareByKey := map[*bls_sig.PublicKey]*bls_sig.PublicKey{pubkey: pubkey} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, pubShareByKey, 0)
	require.NoError(t, err)

	unsigned := &eth2api.VersionedValidatorRegistration{
		Version: spec.BuilderVersionV1,
		V1:      testutil.RandomValidatorRegistration(t),
	}
	unsigned.V1.Pubkey = eth2Pubkey
	unsigned.V1.Timestamp, err = bmock.GenesisTime(ctx) // Set timestamp to genesis which should result in epoch 0 and slot 0.
	require.NoError(t, err)

	// Sign validator (builder) registration
	sigRoot, err := unsigned.V1.HashTreeRoot()
	require.NoError(t, err)

	domain, err := signing.GetDomain(ctx, bmock, signing.DomainApplicationBuilder, 0)
	require.NoError(t, err)

	sigData, err := (&eth2p0.SigningData{ObjectRoot: sigRoot, Domain: domain}).HashTreeRoot()
	require.NoError(t, err)

	s, err := tbls.Sign(secret, sigData[:])
	require.NoError(t, err)

	sigEth2 := tblsconv.SigToETH2(s)
	signed := &eth2api.VersionedSignedValidatorRegistration{
		Version: spec.BuilderVersionV1,
		V1: &eth2v1.SignedValidatorRegistration{
			Message:   unsigned.V1,
			Signature: sigEth2,
		},
	}

	// Register subscriber
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Equal(t, core.NewBuilderRegistrationDuty(0), duty)

		registration, ok := set[corePubKey].SignedData.(core.VersionedSignedValidatorRegistration)
		require.True(t, ok)
		require.Equal(t, *signed, registration.VersionedSignedValidatorRegistration)

		return nil
	})

	err = vapi.SubmitRegistrations(ctx, []*eth2api.VersionedSignedValidatorRegistration{signed})
	require.NoError(t, err)
}

func TestComponent_SubmitValidatorRegistrationInvalidSignature(t *testing.T) {
	ctx := context.Background()

	// Create keys (just use normal keys, not split tbls)
	pubkey, secret, err := tbls.Keygen()
	require.NoError(t, err)

	// Convert pubkey
	eth2Pubkey, err := tblsconv.KeyToETH2(pubkey)
	require.NoError(t, err)
	corePubKey, err := tblsconv.KeyToCore(pubkey)
	require.NoError(t, err)
	pubShareByKey := map[*bls_sig.PublicKey]*bls_sig.PublicKey{pubkey: pubkey} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, pubShareByKey, 0)
	require.NoError(t, err)

	unsigned := &eth2api.VersionedValidatorRegistration{
		Version: spec.BuilderVersionV1,
		V1:      testutil.RandomValidatorRegistration(t),
	}
	unsigned.V1.Pubkey = eth2Pubkey
	unsigned.V1.Timestamp, err = bmock.GenesisTime(ctx) // Set timestamp to genesis which should result in epoch 0 and slot 0.
	require.NoError(t, err)

	vapi.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{corePubKey: nil}, nil
	})

	// Add invalid Signature to validator (builder) registration

	s, err := tbls.Sign(secret, []byte("invalid msg"))
	require.NoError(t, err)

	sigEth2 := tblsconv.SigToETH2(s)
	signed := &eth2api.VersionedSignedValidatorRegistration{
		Version: spec.BuilderVersionV1,
		V1: &eth2v1.SignedValidatorRegistration{
			Message:   unsigned.V1,
			Signature: sigEth2,
		},
	}

	err = vapi.SubmitRegistrations(ctx, []*eth2api.VersionedSignedValidatorRegistration{signed})
	require.ErrorContains(t, err, "invalid signature")
}
