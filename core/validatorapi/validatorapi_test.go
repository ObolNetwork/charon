// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatorapi_test

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/validatorapi"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
	"github.com/obolnetwork/charon/testutil/validatormock"
)

func TestComponent_ValidSubmitAttestations(t *testing.T) {
	ctx := context.Background()
	eth2Cl, err := beaconmock.New()
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

	component, err := validatorapi.NewComponentInsecure(t, eth2Cl, 0)
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
	eth2Cl, err := beaconmock.New()
	require.NoError(t, err)

	const (
		slot       = 123
		commIdx    = 456
		vIdx       = 1
		valCommIdx = vIdx
		commLen    = 8
	)

	component, err := validatorapi.NewComponentInsecure(t, eth2Cl, vIdx)
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
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	// Configure validator
	const (
		vIdx     = 1
		shareIdx = 1
	)

	validator := beaconmock.ValidatorSetA[vIdx]
	validator.Validator.PublicKey = eth2p0.BLSPubKey(pubkey)
	require.NoError(t, err)

	// Convert pubkey
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New(
		beaconmock.WithValidatorSet(beaconmock.ValidatorSet{vIdx: validator}),
		beaconmock.WithDeterministicAttesterDuties(0), // All duties in first slot of epoch.
	)
	require.NoError(t, err)

	epochSlot, err := bmock.SlotsPerEpoch(ctx)
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	vapi.RegisterPubKeyByAttestation(func(ctx context.Context, slot, commIdx, valCommIdx int64) (core.PubKey, error) {
		require.EqualValues(t, slot, epochSlot)
		require.EqualValues(t, commIdx, vIdx)
		require.EqualValues(t, valCommIdx, 0)

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

	signer, err := validatormock.NewSigner(secret)
	require.NoError(t, err)

	// Run attestation using validator mock
	attester := validatormock.NewSlotAttester(
		bmock,
		eth2p0.Slot(epochSlot),
		signer,
		[]eth2p0.BLSPubKey{validator.Validator.PublicKey},
	)

	require.NoError(t, attester.Prepare(ctx))
	require.NoError(t, attester.Attest(ctx))
}

// TestSignAndVerify signs and verifies the signature.
// Test input and output obtained from prysm/validator/client/attest_test.go#TestSignAttestation.
func TestSignAndVerify(t *testing.T) {
	ctx := context.Background()

	// Create key pair
	secretKey := *(*tbls.PrivateKey)(padTo([]byte{1}, 32))

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
	pubkey, err := tbls.SecretToPublicKey(secretKey)
	require.NoError(t, err)
	eth2Pubkey := eth2p0.BLSPubKey(pubkey)

	signer, err := validatormock.NewSigner(secretKey)
	require.NoError(t, err)

	// Sign
	sig, err := signer(eth2Pubkey, sigDataBytes[:])
	require.NoError(t, err)

	// Assert signature
	require.Equal(t, "0xb6a60f8497bd328908be83634d045dd7a32f5e246b2c4031fc2f316983f362e36fc27fd3d6d5a2b15b4dbff38804ffb10b1719b7ebc54e9cbf3293fd37082bc0fc91f79d70ce5b04ff13de3c8e10bb41305bfdbe921a43792c12624f225ee865",
		fmt.Sprintf("%#x", sig))

	// Convert pubkey
	shareIdx := 1
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	// Setup validatorapi component.
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)
	vapi.RegisterPubKeyByAttestation(func(context.Context, int64, int64, int64) (core.PubKey, error) {
		return core.PubKeyFromBytes(pubkey[:])
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
	eth2Cl, err := beaconmock.New()
	require.NoError(t, err)

	const (
		slot = 123
		vIdx = 1
	)

	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(context.Background())
	require.NoError(t, err)

	epoch := eth2p0.Epoch(uint64(slot) / slotsPerEpoch)

	component, err := validatorapi.NewComponentInsecure(t, eth2Cl, vIdx)
	require.NoError(t, err)

	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pk, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	msg := []byte("randao reveal")
	sig, err := tbls.Sign(secret, msg)
	require.NoError(t, err)

	randao := eth2p0.BLSSignature(sig)
	pubkey, err := core.PubKeyFromBytes(pk[:])
	require.NoError(t, err)

	block1 := &eth2spec.VersionedBeaconBlock{
		Version: eth2spec.DataVersionPhase0,
		Phase0:  testutil.RandomPhase0BeaconBlock(),
	}
	block1.Phase0.Slot = slot
	block1.Phase0.ProposerIndex = vIdx
	block1.Phase0.Body.RANDAOReveal = randao

	component.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{pubkey: nil}, nil
	})

	component.RegisterAwaitBeaconBlock(func(ctx context.Context, slot int64) (*eth2spec.VersionedBeaconBlock, error) {
		return block1, nil
	})

	component.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Equal(t, set, core.ParSignedDataSet{
			pubkey: core.NewPartialSignedRandao(epoch, randao, vIdx),
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
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	const (
		vIdx     = 1
		shareIdx = 1
		slot     = 123
		epoch    = eth2p0.Epoch(3)
	)

	// Convert pubkey
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	// Prepare unsigned beacon block
	msg := []byte("randao reveal")
	sig, err := tbls.Sign(secret, msg)
	require.NoError(t, err)

	randao := eth2p0.BLSSignature(sig)
	unsignedBlock := &eth2spec.VersionedBeaconBlock{
		Version: eth2spec.DataVersionPhase0,
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

	signedBlock := &eth2spec.VersionedSignedBeaconBlock{
		Version: eth2spec.DataVersionPhase0,
		Phase0: &eth2p0.SignedBeaconBlock{
			Message:   unsignedBlock.Phase0,
			Signature: eth2p0.BLSSignature(s),
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
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	const (
		vIdx     = 1
		shareIdx = 1
		slot     = 123
	)

	// Convert pubkey
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	// Prepare unsigned beacon block
	msg := []byte("randao reveal")
	sig, err := tbls.Sign(secret, msg)
	require.NoError(t, err)

	vapi.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{corePubKey: nil}, nil
	})

	// Add invalid Signature to beacon block
	s, err := tbls.Sign(secret, []byte("invalid msg"))
	require.NoError(t, err)

	unsignedBlock := testutil.RandomPhase0BeaconBlock()
	unsignedBlock.Body.RANDAOReveal = eth2p0.BLSSignature(sig)
	unsignedBlock.Slot = slot
	unsignedBlock.ProposerIndex = vIdx

	signedBlock := &eth2spec.VersionedSignedBeaconBlock{
		Version: eth2spec.DataVersionPhase0,
		Phase0: &eth2p0.SignedBeaconBlock{
			Message:   unsignedBlock,
			Signature: eth2p0.BLSSignature(s),
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
	require.ErrorContains(t, err, "signature not verified")
}

func TestComponent_SubmitBeaconBlockInvalidBlock(t *testing.T) {
	ctx := context.Background()
	shareIdx := 1
	// Create keys (just use normal keys, not split tbls)
	pubkey := testutil.RandomCorePubKey(t)

	pkb, err := pubkey.Bytes()
	require.NoError(t, err)

	tblsPubkey := *(*tbls.PublicKey)(pkb)
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{pubkey: {shareIdx: tblsPubkey}} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	vapi.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{pubkey: nil}, nil
	})

	// invalid block scenarios
	tests := []struct {
		name   string
		block  *eth2spec.VersionedSignedBeaconBlock
		errMsg string
	}{
		{
			name:   "no phase 0 block",
			block:  &eth2spec.VersionedSignedBeaconBlock{Version: eth2spec.DataVersionPhase0},
			errMsg: "no phase0 block",
		},
		{
			name:   "no altair block",
			block:  &eth2spec.VersionedSignedBeaconBlock{Version: eth2spec.DataVersionAltair},
			errMsg: "no altair block",
		},
		{
			name:   "no bellatrix block",
			block:  &eth2spec.VersionedSignedBeaconBlock{Version: eth2spec.DataVersionBellatrix},
			errMsg: "no bellatrix block",
		},
		{
			name:   "no capella block",
			block:  &eth2spec.VersionedSignedBeaconBlock{Version: eth2spec.DataVersionCapella},
			errMsg: "no capella block",
		},
		{
			name:   "none",
			block:  &eth2spec.VersionedSignedBeaconBlock{Version: eth2spec.DataVersion(5)},
			errMsg: "unknown version",
		},
		{
			name: "no phase 0 sig",
			block: &eth2spec.VersionedSignedBeaconBlock{
				Version: eth2spec.DataVersionPhase0,
				Phase0: &eth2p0.SignedBeaconBlock{
					Message:   &eth2p0.BeaconBlock{Slot: eth2p0.Slot(123), Body: testutil.RandomPhase0BeaconBlockBody()},
					Signature: eth2p0.BLSSignature{},
				},
			},
			errMsg: "no signature found",
		},
		{
			name: "no altair sig",
			block: &eth2spec.VersionedSignedBeaconBlock{
				Version: eth2spec.DataVersionAltair,
				Altair: &altair.SignedBeaconBlock{
					Message:   &altair.BeaconBlock{Slot: eth2p0.Slot(123), Body: testutil.RandomAltairBeaconBlockBody()},
					Signature: eth2p0.BLSSignature{},
				},
			},
			errMsg: "no signature found",
		},
		{
			name: "no bellatrix sig",
			block: &eth2spec.VersionedSignedBeaconBlock{
				Version: eth2spec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBeaconBlock{
					Message:   &bellatrix.BeaconBlock{Slot: eth2p0.Slot(123), Body: testutil.RandomBellatrixBeaconBlockBody()},
					Signature: eth2p0.BLSSignature{},
				},
			},
			errMsg: "no signature found",
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
	eth2Cl, err := beaconmock.New()
	require.NoError(t, err)

	const (
		slot = 123
		vIdx = 1
	)

	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(context.Background())
	require.NoError(t, err)

	epoch := eth2p0.Epoch(uint64(slot) / slotsPerEpoch)

	component, err := validatorapi.NewComponentInsecure(t, eth2Cl, vIdx)
	require.NoError(t, err)

	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pk, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	msg := []byte("randao reveal")
	sig, err := tbls.Sign(secret, msg)
	require.NoError(t, err)

	randao := eth2p0.BLSSignature(sig)
	pubkey, err := core.PubKeyFromBytes(pk[:])
	require.NoError(t, err)

	block1 := &eth2api.VersionedBlindedBeaconBlock{
		Version:   eth2spec.DataVersionPhase0,
		Bellatrix: testutil.RandomBellatrixBlindedBeaconBlock(),
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
			pubkey: core.NewPartialSignedRandao(epoch, randao, vIdx),
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
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	const (
		vIdx     = 1
		shareIdx = 1
		slot     = 123
		epoch    = eth2p0.Epoch(3)
	)

	// Convert pubkey
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderTrue, nil)
	require.NoError(t, err)

	// Prepare unsigned beacon block
	msg := []byte("randao reveal")
	sig, err := tbls.Sign(secret, msg)
	require.NoError(t, err)

	unsignedBlindedBlock := testutil.RandomCapellaBlindedBeaconBlock()
	unsignedBlindedBlock.Body.RANDAOReveal = eth2p0.BLSSignature(sig)
	unsignedBlindedBlock.Slot = slot
	unsignedBlindedBlock.ProposerIndex = vIdx

	vapi.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{corePubKey: nil}, nil
	})

	// Sign blinded beacon block
	sigRoot, err := unsignedBlindedBlock.HashTreeRoot()
	require.NoError(t, err)

	domain, err := signing.GetDomain(ctx, bmock, signing.DomainBeaconProposer, epoch)
	require.NoError(t, err)

	sigData, err := (&eth2p0.SigningData{ObjectRoot: sigRoot, Domain: domain}).HashTreeRoot()
	require.NoError(t, err)

	s, err := tbls.Sign(secret, sigData[:])
	require.NoError(t, err)

	signedBlindedBlock := &eth2api.VersionedSignedBlindedBeaconBlock{
		Version: eth2spec.DataVersionCapella,
		Capella: &eth2capella.SignedBlindedBeaconBlock{
			Message:   unsignedBlindedBlock,
			Signature: eth2p0.BLSSignature(s),
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
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	const (
		vIdx     = 1
		shareIdx = 1
		slot     = 123
	)

	// Convert pubkey
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderTrue, nil)
	require.NoError(t, err)

	// Prepare unsigned beacon block
	msg := []byte("randao reveal")
	sig, err := tbls.Sign(secret, msg)
	require.NoError(t, err)

	unsignedBlindedBlock := testutil.RandomCapellaBlindedBeaconBlock()
	unsignedBlindedBlock.Body.RANDAOReveal = eth2p0.BLSSignature(sig)
	unsignedBlindedBlock.Slot = slot
	unsignedBlindedBlock.ProposerIndex = vIdx

	vapi.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{corePubKey: nil}, nil
	})

	// Add invalid Signature to blinded beacon block

	s, err := tbls.Sign(secret, []byte("invalid msg"))
	require.NoError(t, err)

	signedBlindedBlock := &eth2api.VersionedSignedBlindedBeaconBlock{
		Version: eth2spec.DataVersionCapella,
		Capella: &eth2capella.SignedBlindedBeaconBlock{
			Message:   unsignedBlindedBlock,
			Signature: eth2p0.BLSSignature(s),
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
	require.ErrorContains(t, err, "signature not verified")
}

func TestComponent_SubmitBlindedBeaconBlockInvalidBlock(t *testing.T) {
	ctx := context.Background()
	shareIdx := 1
	// Create keys (just use normal keys, not split tbls)
	pubkey := testutil.RandomCorePubKey(t)

	// Convert pubkey
	pkb, err := pubkey.Bytes()
	require.NoError(t, err)

	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{pubkey: {shareIdx: *(*tbls.PublicKey)(pkb)}} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderTrue, nil)
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
			block:  &eth2api.VersionedSignedBlindedBeaconBlock{Version: eth2spec.DataVersionBellatrix},
			errMsg: "no bellatrix block",
		},
		{
			name:  "no deneb block",
			block: &eth2api.VersionedSignedBlindedBeaconBlock{Version: eth2spec.DataVersionDeneb},
		},
		{
			name:   "none",
			block:  &eth2api.VersionedSignedBlindedBeaconBlock{Version: eth2spec.DataVersion(5)},
			errMsg: "unsupported version",
		},
		{
			name: "no bellatrix sig",
			block: &eth2api.VersionedSignedBlindedBeaconBlock{
				Version: eth2spec.DataVersionBellatrix,
				Bellatrix: &eth2bellatrix.SignedBlindedBeaconBlock{
					Message:   &eth2bellatrix.BlindedBeaconBlock{Slot: eth2p0.Slot(123), Body: testutil.RandomBellatrixBlindedBeaconBlockBody()},
					Signature: eth2p0.BLSSignature{},
				},
			},
			errMsg: "no signature found",
		},
		{
			name: "no capella sig",
			block: &eth2api.VersionedSignedBlindedBeaconBlock{
				Version: eth2spec.DataVersionCapella,
				Capella: &eth2capella.SignedBlindedBeaconBlock{
					Message:   &eth2capella.BlindedBeaconBlock{Slot: eth2p0.Slot(123), Body: testutil.RandomCapellaBlindedBeaconBlockBody()},
					Signature: eth2p0.BLSSignature{},
				},
			},
			errMsg: "no signature found",
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
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	const (
		vIdx     = 2
		shareIdx = 1
		epoch    = 10
	)

	// Convert pubkey
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	// Prep beacon mock validators
	validator := beaconmock.ValidatorSetA[vIdx]
	validator.Validator.PublicKey = eth2p0.BLSPubKey(pubkey)
	require.NoError(t, err)

	// Configure beacon mock
	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(beaconmock.ValidatorSetA))
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
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
		Signature: eth2p0.BLSSignature(sig),
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

	const (
		vIdx     = 2
		shareIdx = 1
	)

	// Create keys (just use normal keys, not split tbls)
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	validator := beaconmock.ValidatorSetA[vIdx]
	validator.Validator.PublicKey = eth2p0.BLSPubKey(pubkey)
	require.NoError(t, err)

	// Configure beacon mock
	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(beaconmock.ValidatorSetA))
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
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
	exit.Signature = eth2p0.BLSSignature(sig)

	err = vapi.SubmitVoluntaryExit(ctx, exit)
	require.ErrorContains(t, err, "signature not verified")
}

func TestComponent_Duties(t *testing.T) {
	ctx := context.Background()

	// Configure validator
	const (
		vIdx     = 123
		shareIdx = 1
		epch     = 456
	)

	// Create pubkey and pubshare
	eth2Pubkey := testutil.RandomEth2PubKey(t)
	eth2Share := testutil.RandomEth2PubKey(t)

	pubshare := tbls.PublicKey(eth2Share)
	pubkey := tbls.PublicKey(eth2Pubkey)
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)

	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubshare}}
	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	t.Run("proposer_duties", func(t *testing.T) {
		bmock.ProposerDutiesFunc = func(ctx context.Context, epoch eth2p0.Epoch, indices []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
			require.Equal(t, epoch, eth2p0.Epoch(epch))
			require.Equal(t, []eth2p0.ValidatorIndex{eth2p0.ValidatorIndex(vIdx)}, indices)

			return []*eth2v1.ProposerDuty{{
				PubKey:         eth2Pubkey,
				ValidatorIndex: vIdx,
			}}, nil
		}

		// Construct the validator api component
		vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
		require.NoError(t, err)
		duties, err := vapi.ProposerDuties(ctx, eth2p0.Epoch(epch), []eth2p0.ValidatorIndex{eth2p0.ValidatorIndex(vIdx)})
		require.NoError(t, err)
		require.Len(t, duties, 1)
		require.Equal(t, duties[0].PubKey, eth2Share)
	})

	t.Run("attester_duties", func(t *testing.T) {
		bmock.AttesterDutiesFunc = func(_ context.Context, epoch eth2p0.Epoch, indices []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
			require.Equal(t, epoch, eth2p0.Epoch(epch))
			require.Equal(t, []eth2p0.ValidatorIndex{eth2p0.ValidatorIndex(vIdx)}, indices)

			return []*eth2v1.AttesterDuty{{
				PubKey:         eth2Pubkey,
				ValidatorIndex: vIdx,
			}}, nil
		}

		// Construct the validator api component
		vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
		require.NoError(t, err)
		duties, err := vapi.AttesterDuties(ctx, eth2p0.Epoch(epch), []eth2p0.ValidatorIndex{eth2p0.ValidatorIndex(vIdx)})
		require.NoError(t, err)
		require.Len(t, duties, 1)
		require.Equal(t, duties[0].PubKey, eth2Share)
	})

	t.Run("sync_committee_duties", func(t *testing.T) {
		bmock.SyncCommitteeDutiesFunc = func(ctx context.Context, epoch eth2p0.Epoch, indices []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error) {
			require.Equal(t, epoch, eth2p0.Epoch(epch))
			require.Equal(t, []eth2p0.ValidatorIndex{eth2p0.ValidatorIndex(vIdx)}, indices)

			return []*eth2v1.SyncCommitteeDuty{{
				PubKey:         eth2Pubkey,
				ValidatorIndex: vIdx,
			}}, nil
		}

		// Construct the validator api component
		vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
		require.NoError(t, err)
		duties, err := vapi.SyncCommitteeDuties(ctx, eth2p0.Epoch(epch), []eth2p0.ValidatorIndex{eth2p0.ValidatorIndex(vIdx)})
		require.NoError(t, err)
		require.Len(t, duties, 1)
		require.Equal(t, duties[0].PubKey, eth2Share)
	})
}

func TestComponent_SubmitValidatorRegistration(t *testing.T) {
	ctx := context.Background()
	shareIdx := 1
	// Create keys (just use normal keys, not split tbls)
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	// Convert pubkey
	eth2Pubkey := eth2p0.BLSPubKey(pubkey)
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderTrue, nil)
	require.NoError(t, err)

	unsigned := testutil.RandomValidatorRegistration(t)
	unsigned.Pubkey = eth2Pubkey
	unsigned.Timestamp, err = bmock.GenesisTime(ctx) // Set timestamp to genesis which should result in epoch 0 and slot 0.
	require.NoError(t, err)

	// Sign validator (builder) registration
	sigRoot, err := unsigned.HashTreeRoot()
	require.NoError(t, err)

	sigData, err := signing.GetDataRoot(ctx, bmock, signing.DomainApplicationBuilder, 0, sigRoot)
	require.NoError(t, err)

	s, err := tbls.Sign(secret, sigData[:])
	require.NoError(t, err)

	signed := &eth2api.VersionedSignedValidatorRegistration{
		Version: eth2spec.BuilderVersionV1,
		V1: &eth2v1.SignedValidatorRegistration{
			Message:   unsigned,
			Signature: eth2p0.BLSSignature(s),
		},
	}

	output := make(chan core.ParSignedDataSet, 1)

	// Register subscriber
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Equal(t, core.NewBuilderRegistrationDuty(0), duty)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case output <- set:
		}

		return nil
	})

	err = vapi.SubmitValidatorRegistrations(ctx, []*eth2api.VersionedSignedValidatorRegistration{signed})
	require.NoError(t, err)

	// Assert output
	actualData := <-output
	registration, ok := actualData[corePubKey].SignedData.(core.VersionedSignedValidatorRegistration)
	require.True(t, ok)
	require.Equal(t, *signed, registration.VersionedSignedValidatorRegistration)

	// Assert incorrect pubkey registration is swallowed
	close(output) // Panic if registration is not swallowed
	signed.V1.Message.Pubkey = testutil.RandomEth2PubKey(t)
	err = vapi.SubmitValidatorRegistrations(ctx, []*eth2api.VersionedSignedValidatorRegistration{signed})
	require.NoError(t, err)
}

func TestComponent_SubmitValidatorRegistrationInvalidSignature(t *testing.T) {
	ctx := context.Background()
	shareIdx := 1
	// Create keys (just use normal keys, not split tbls)
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	// Convert pubkey
	eth2Pubkey := eth2p0.BLSPubKey(pubkey)
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderTrue, nil)
	require.NoError(t, err)

	unsigned := testutil.RandomValidatorRegistration(t)
	unsigned.Pubkey = eth2Pubkey
	unsigned.Timestamp, err = bmock.GenesisTime(ctx) // Set timestamp to genesis which should result in epoch 0 and slot 0.
	require.NoError(t, err)

	vapi.RegisterGetDutyDefinition(func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{corePubKey: nil}, nil
	})

	// Add invalid Signature to validator (builder) registration

	s, err := tbls.Sign(secret, []byte("invalid msg"))
	require.NoError(t, err)

	signed := &eth2api.VersionedSignedValidatorRegistration{
		Version: eth2spec.BuilderVersionV1,
		V1: &eth2v1.SignedValidatorRegistration{
			Message:   unsigned,
			Signature: eth2p0.BLSSignature(s),
		},
	}

	err = vapi.SubmitValidatorRegistrations(ctx, []*eth2api.VersionedSignedValidatorRegistration{signed})
	require.ErrorContains(t, err, "signature not verified")
}

func TestComponent_TekuProposerConfig(t *testing.T) {
	ctx := context.Background()
	const (
		zeroAddr     = "0x0000000000000000000000000000000000000000"
		feeRecipient = "0x123456"
		shareIdx     = 1
	)
	// Create keys (just use normal keys, not split tbls)
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	// Convert pubkey
	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	// Configure beacon mock
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, func(core.PubKey) string {
		return feeRecipient
	}, testutil.BuilderTrue, nil)
	require.NoError(t, err)

	resp, err := vapi.ProposerConfig(ctx)
	require.NoError(t, err)

	pk, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)

	genesis, err := bmock.GenesisTime(ctx)
	require.NoError(t, err)
	slotDuration, err := bmock.SlotDuration(ctx)
	require.NoError(t, err)

	eth2pk, err := pk.ToETH2()
	require.NoError(t, err)

	require.Equal(t, &eth2exp.ProposerConfigResponse{
		Proposers: map[eth2p0.BLSPubKey]eth2exp.ProposerConfig{
			eth2pk: {
				FeeRecipient: feeRecipient,
				Builder: eth2exp.Builder{
					Enabled:  true,
					GasLimit: 30000000,
					Overrides: map[string]string{
						"timestamp":  fmt.Sprint(genesis.Add(slotDuration).Unix()),
						"public_key": string(pk),
					},
				},
			},
		},
		Default: eth2exp.ProposerConfig{
			FeeRecipient: zeroAddr,
			Builder: eth2exp.Builder{
				Enabled:  false,
				GasLimit: 30000000,
			},
		},
	}, resp)
}

func TestComponent_AggregateBeaconCommitteeSelections(t *testing.T) {
	ctx := context.Background()

	const slot = 99

	valSet := beaconmock.ValidatorSetA
	eth2Cl, err := beaconmock.New(beaconmock.WithValidatorSet(valSet))
	require.NoError(t, err)

	vapi, err := validatorapi.NewComponentInsecure(t, eth2Cl, 0)
	require.NoError(t, err)

	selections := []*eth2exp.BeaconCommitteeSelection{
		{
			ValidatorIndex: valSet[1].Index,
			Slot:           slot,
			SelectionProof: testutil.RandomEth2Signature(),
		}, {
			ValidatorIndex: valSet[2].Index,
			Slot:           slot,
			SelectionProof: testutil.RandomEth2Signature(),
		},
	}

	vapi.RegisterAwaitAggSigDB(func(_ context.Context, duty core.Duty, pk core.PubKey) (core.SignedData, error) {
		require.Equal(t, core.NewPrepareAggregatorDuty(slot), duty)
		for _, val := range valSet {
			pkEth2, err := pk.ToETH2()
			require.NoError(t, err)
			if pkEth2 != val.Validator.PublicKey {
				continue
			}
			for _, selection := range selections {
				if selection.ValidatorIndex == val.Index {
					return core.NewBeaconCommitteeSelection(selection), nil
				}
			}
		}

		return nil, errors.New("unknown public key")
	})

	actual, err := vapi.AggregateBeaconCommitteeSelections(ctx, selections)
	require.NoError(t, err)

	// Sort by VIdx before comparing
	sort.Slice(actual, func(i, j int) bool {
		return actual[i].ValidatorIndex < actual[j].ValidatorIndex
	})
	require.Equal(t, selections, actual)
}

func TestComponent_SubmitAggregateAttestations(t *testing.T) {
	ctx := context.Background()

	const vIdx = 1

	agg := &eth2p0.SignedAggregateAndProof{
		Message: &eth2p0.AggregateAndProof{
			AggregatorIndex: vIdx,
			Aggregate:       testutil.RandomAttestation(),
			SelectionProof:  testutil.RandomEth2Signature(),
		},
		Signature: testutil.RandomEth2Signature(),
	}

	slot := agg.Message.Aggregate.Data.Slot
	pubkey := beaconmock.ValidatorSetA[vIdx].Validator.PublicKey

	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(beaconmock.ValidatorSetA))
	require.NoError(t, err)

	vapi, err := validatorapi.NewComponentInsecure(t, bmock, 0)
	require.NoError(t, err)

	vapi.Subscribe(func(_ context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Equal(t, core.NewAggregatorDuty(int64(slot)), duty)

		pk, err := core.PubKeyFromBytes(pubkey[:])
		require.NoError(t, err)

		data, ok := set[pk]
		require.True(t, ok)
		require.Equal(t, core.NewPartialSignedAggregateAndProof(agg, 0), data)

		return nil
	})

	require.NoError(t, vapi.SubmitAggregateAttestations(ctx, []*eth2p0.SignedAggregateAndProof{agg}))
}

func TestComponent_SubmitAggregateAttestationVerify(t *testing.T) {
	const shareIdx = 1
	var (
		ctx = context.Background()
		val = testutil.RandomValidator(t)
	)

	// Create keys (just use normal keys, not split tbls)
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)

	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	val.Validator.PublicKey = eth2p0.BLSPubKey(pubkey)

	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(beaconmock.ValidatorSet{val.Index: val}))
	require.NoError(t, err)

	slot := eth2p0.Slot(99)
	aggProof := &eth2p0.AggregateAndProof{
		AggregatorIndex: val.Index,
		Aggregate:       testutil.RandomAttestation(),
	}
	aggProof.Aggregate.Data.Slot = slot
	aggProof.SelectionProof = signBeaconSelection(t, bmock, secret, slot)
	signedAggProof := &eth2p0.SignedAggregateAndProof{
		Message:   aggProof,
		Signature: signAggregationAndProof(t, bmock, secret, aggProof),
	}

	// Construct the validator api component
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	done := make(chan struct{})
	// Collect submitted partial signature.
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Len(t, set, 1)
		_, ok := set[core.PubKeyFrom48Bytes(val.Validator.PublicKey)]
		require.True(t, ok)
		close(done)

		return nil
	})

	err = vapi.SubmitAggregateAttestations(ctx, []*eth2p0.SignedAggregateAndProof{signedAggProof})
	require.NoError(t, err)
	<-done
}

func TestComponent_SubmitSyncCommitteeMessages(t *testing.T) {
	const vIdx = 1

	var (
		ctx    = context.Background()
		msg    = testutil.RandomSyncCommitteeMessage()
		pubkey = beaconmock.ValidatorSetA[vIdx].Validator.PublicKey
		count  = 0 // No of times the subscription function is called.
	)

	msg.ValidatorIndex = vIdx

	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(beaconmock.ValidatorSetA))
	require.NoError(t, err)

	vapi, err := validatorapi.NewComponentInsecure(t, bmock, 0)
	require.NoError(t, err)

	vapi.Subscribe(func(_ context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Equal(t, core.NewSyncMessageDuty(int64(msg.Slot)), duty)

		pk, err := core.PubKeyFromBytes(pubkey[:])
		require.NoError(t, err)

		data, ok := set[pk]
		require.True(t, ok)
		require.Equal(t, core.NewPartialSignedSyncMessage(msg, 0), data)
		count++

		return nil
	})

	require.NoError(t, vapi.SubmitSyncCommitteeMessages(ctx, []*altair.SyncCommitteeMessage{msg}))
	require.Equal(t, count, 1)
}

func TestComponent_SubmitSyncCommitteeContributions(t *testing.T) {
	const vIdx = 1

	var (
		count        = 0 // No of times the subscription function is called.
		ctx          = context.Background()
		contrib      = testutil.RandomSignedSyncContributionAndProof()
		pubkey       = beaconmock.ValidatorSetA[vIdx].Validator.PublicKey
		expectedDuty = core.NewSyncContributionDuty(int64(contrib.Message.Contribution.Slot))
	)

	contrib.Message.AggregatorIndex = vIdx

	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(beaconmock.ValidatorSetA))
	require.NoError(t, err)

	vapi, err := validatorapi.NewComponentInsecure(t, bmock, 0)
	require.NoError(t, err)

	vapi.Subscribe(func(_ context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Equal(t, expectedDuty, duty)

		pk, err := core.PubKeyFromBytes(pubkey[:])
		require.NoError(t, err)

		data, ok := set[pk]
		require.True(t, ok)
		require.Equal(t, core.NewPartialSignedSyncContributionAndProof(contrib, 0), data)
		count++

		return nil
	})

	require.NoError(t, vapi.SubmitSyncCommitteeContributions(ctx, []*altair.SignedContributionAndProof{contrib}))
	require.Equal(t, count, 1)
}

func TestComponent_SubmitSyncCommitteeContributionsVerify(t *testing.T) {
	const shareIdx = 1
	var (
		ctx        = context.Background()
		val        = testutil.RandomValidator(t)
		slot       = eth2p0.Slot(50)
		subcommIdx = eth2p0.CommitteeIndex(1)
	)

	// Create keys (just use normal keys, not split tbls).
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

	val.Validator.PublicKey = eth2p0.BLSPubKey(pubkey)

	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(beaconmock.ValidatorSet{val.Index: val}))
	require.NoError(t, err)

	// Create contribution and proof.
	contribAndProof := &altair.ContributionAndProof{
		AggregatorIndex: val.Index,
		Contribution:    testutil.RandomSyncCommitteeContribution(),
	}
	contribAndProof.Contribution.Slot = slot
	contribAndProof.Contribution.SubcommitteeIndex = uint64(subcommIdx)
	contribAndProof.SelectionProof = syncCommSelectionProof(t, bmock, secret, slot, subcommIdx)

	signedContribAndProof := &altair.SignedContributionAndProof{
		Message:   contribAndProof,
		Signature: signContributionAndProof(t, bmock, secret, contribAndProof),
	}

	// Construct validatorapi component.
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	done := make(chan struct{})
	// Collect submitted partial signature.
	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Len(t, set, 1)
		_, ok := set[core.PubKeyFrom48Bytes(val.Validator.PublicKey)]
		require.True(t, ok)
		close(done)

		return nil
	})

	err = vapi.SubmitSyncCommitteeContributions(ctx, []*altair.SignedContributionAndProof{signedContribAndProof})
	require.NoError(t, err)
	<-done
}

func TestComponent_GetAllValidators(t *testing.T) {
	const (
		totalVals      = 10
		numClusterVals = 4
		shareIdx       = 1
	)

	validatorSet := testutil.RandomValidatorSet(t, totalVals)

	// Pick numClusterVals from validator set.
	var (
		clusterVals       []*eth2v1.Validator
		allPubSharesByKey = make(map[core.PubKey]map[int]tbls.PublicKey)
		keyByPubshare     = make(map[tbls.PublicKey]core.PubKey)
	)
	i := numClusterVals
	for _, val := range validatorSet {
		i--

		clusterVals = append(clusterVals, val)
		pubshare, err := tblsconv.PubkeyFromCore(testutil.RandomCorePubKey(t))
		require.NoError(t, err)

		corePubkey := core.PubKeyFrom48Bytes(val.Validator.PublicKey)
		allPubSharesByKey[corePubkey] = make(map[int]tbls.PublicKey)
		allPubSharesByKey[core.PubKeyFrom48Bytes(val.Validator.PublicKey)][shareIdx] = pubshare
		keyByPubshare[pubshare] = corePubkey

		if i == 0 {
			break
		}
	}

	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(validatorSet))
	require.NoError(t, err)

	// Construct validatorapi component.
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	vals, err := vapi.Validators(context.Background(), "head", nil)
	require.NoError(t, err)
	require.Len(t, vals, totalVals)

	for _, val := range clusterVals {
		pubshare, err := tblsconv.PubkeyFromBytes(vals[val.Index].Validator.PublicKey[:])
		require.NoError(t, err)

		eth2Pubkey, err := keyByPubshare[pubshare].ToETH2()
		require.NoError(t, err)
		require.Equal(t, validatorSet[val.Index].Validator.PublicKey, eth2Pubkey)
	}
}

func TestComponent_GetClusterValidatorsWithError(t *testing.T) {
	const (
		numClusterVals = 4
		shareIdx       = 1
	)

	validatorSet := testutil.RandomValidatorSet(t, numClusterVals)
	var indices []eth2p0.ValidatorIndex
	for vidx := range validatorSet {
		indices = append(indices, vidx)
	}

	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(validatorSet))
	require.NoError(t, err)

	// Construct validatorapi component.
	vapi, err := validatorapi.NewComponent(bmock, make(map[core.PubKey]map[int]tbls.PublicKey), shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	_, err = vapi.Validators(context.Background(), "head", indices)
	require.ErrorContains(t, err, "pubshare not found")
}

func TestComponent_AggregateSyncCommitteeSelectionsVerify(t *testing.T) {
	const (
		slot     = 0
		shareIdx = 1
		vIdxA    = 1
		vIdxB    = 2
	)

	var (
		ctx    = context.Background()
		valSet = beaconmock.ValidatorSetA
	)

	// Sync committee selection 1.
	secret1, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey1, err := tbls.SecretToPublicKey(secret1)
	require.NoError(t, err)

	pk1, err := core.PubKeyFromBytes(pubkey1[:])
	require.NoError(t, err)

	valSet[vIdxA].Validator.PublicKey = eth2p0.BLSPubKey(pubkey1)

	selection1 := testutil.RandomSyncCommitteeSelection()
	selection1.ValidatorIndex = valSet[1].Index
	selection1.Slot = slot

	// Sync committee selection 2.
	secret2, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey2, err := tbls.SecretToPublicKey(secret2)
	require.NoError(t, err)

	pk2, err := core.PubKeyFromBytes(pubkey2[:])
	require.NoError(t, err)

	valSet[vIdxB].Validator.PublicKey = eth2p0.BLSPubKey(pubkey2)

	selection2 := testutil.RandomSyncCommitteeSelection()
	selection2.ValidatorIndex = valSet[2].Index
	selection2.Slot = slot

	// Construct beaconmock.
	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(valSet))
	require.NoError(t, err)

	selection1.SelectionProof = syncCommSelectionProof(t, bmock, secret1, slot, selection1.SubcommitteeIndex)
	selection2.SelectionProof = syncCommSelectionProof(t, bmock, secret2, slot, selection2.SubcommitteeIndex)

	selections := []*eth2exp.SyncCommitteeSelection{selection1, selection2}

	// Populate all pubshares map.
	corePubKey1, err := core.PubKeyFromBytes(pubkey1[:])
	require.NoError(t, err)
	corePubKey2, err := core.PubKeyFromBytes(pubkey2[:])
	require.NoError(t, err)

	allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{
		corePubKey1: {shareIdx: pubkey1},
		corePubKey2: {shareIdx: pubkey2},
	}

	// Construct the validator api component.
	vapi, err := validatorapi.NewComponent(bmock, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
	require.NoError(t, err)

	vapi.RegisterAwaitAggSigDB(func(ctx context.Context, duty core.Duty, pubkey core.PubKey) (core.SignedData, error) {
		require.Equal(t, core.NewPrepareSyncContributionDuty(slot), duty)
		for _, val := range valSet {
			pkEth2, err := pubkey.ToETH2()
			require.NoError(t, err)
			if pkEth2 != val.Validator.PublicKey {
				continue
			}

			for _, selection := range selections {
				if selection.ValidatorIndex == val.Index {
					require.Equal(t, eth2p0.Slot(slot), selection.Slot)

					return core.NewSyncCommitteeSelection(selection), nil
				}
			}
		}

		return nil, errors.New("unknown public key")
	})

	vapi.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		require.Equal(t, duty, core.NewPrepareSyncContributionDuty(slot))

		expect := core.ParSignedDataSet{
			pk1: core.NewPartialSignedSyncCommitteeSelection(selection1, shareIdx),
			pk2: core.NewPartialSignedSyncCommitteeSelection(selection2, shareIdx),
		}

		require.Equal(t, expect, set)

		return nil
	})

	got, err := vapi.AggregateSyncCommitteeSelections(ctx, selections)
	require.NoError(t, err)

	// Sort by VIdx before comparing.
	sort.Slice(got, func(i, j int) bool {
		return got[i].ValidatorIndex < got[j].ValidatorIndex
	})

	require.Equal(t, selections, got)
}

func signAggregationAndProof(t *testing.T, eth2Cl eth2wrap.Client, secret tbls.PrivateKey, aggProof *eth2p0.AggregateAndProof) eth2p0.BLSSignature {
	t.Helper()

	epoch, err := eth2util.EpochFromSlot(context.Background(), eth2Cl, aggProof.Aggregate.Data.Slot)
	require.NoError(t, err)

	dataRoot, err := aggProof.HashTreeRoot()
	require.NoError(t, err)

	return sign(t, eth2Cl, secret, signing.DomainAggregateAndProof, epoch, dataRoot)
}

// syncCommSelectionProof returns the selection_proof corresponding to the provided altair.ContributionAndProof.
// Refer get_sync_committee_selection_proof from https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#aggregation-selection.
func syncCommSelectionProof(t *testing.T, eth2Cl eth2wrap.Client, secret tbls.PrivateKey, slot eth2p0.Slot, subcommIdx eth2p0.CommitteeIndex) eth2p0.BLSSignature {
	t.Helper()

	epoch, err := eth2util.EpochFromSlot(context.Background(), eth2Cl, slot)
	require.NoError(t, err)

	data := altair.SyncAggregatorSelectionData{
		Slot:              slot,
		SubcommitteeIndex: uint64(subcommIdx),
	}

	sigRoot, err := data.HashTreeRoot()
	require.NoError(t, err)

	return sign(t, eth2Cl, secret, signing.DomainSyncCommitteeSelectionProof, epoch, sigRoot)
}

// signContributionAndProof signs the provided altair.SignedContributionAndProof and returns the signature.
// Refer get_contribution_and_proof_signature from https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#broadcast-sync-committee-contribution
func signContributionAndProof(t *testing.T, eth2Cl eth2wrap.Client, secret tbls.PrivateKey, contrib *altair.ContributionAndProof) eth2p0.BLSSignature {
	t.Helper()

	epoch, err := eth2util.EpochFromSlot(context.Background(), eth2Cl, contrib.Contribution.Slot)
	require.NoError(t, err)

	sigRoot, err := contrib.HashTreeRoot()
	require.NoError(t, err)

	return sign(t, eth2Cl, secret, signing.DomainContributionAndProof, epoch, sigRoot)
}

func signBeaconSelection(t *testing.T, eth2Cl eth2wrap.Client, secret tbls.PrivateKey, slot eth2p0.Slot) eth2p0.BLSSignature {
	t.Helper()

	epoch, err := eth2util.EpochFromSlot(context.Background(), eth2Cl, slot)
	require.NoError(t, err)

	dataRoot, err := eth2util.SlotHashRoot(slot)
	require.NoError(t, err)

	return sign(t, eth2Cl, secret, signing.DomainSelectionProof, epoch, dataRoot)
}

func sign(t *testing.T, eth2Cl eth2wrap.Client, secret tbls.PrivateKey, domain signing.DomainName, epoch eth2p0.Epoch, dataRoot eth2p0.Root) eth2p0.BLSSignature {
	t.Helper()
	ctx := context.Background()

	signingRoot, err := signing.GetDataRoot(ctx, eth2Cl, domain, epoch, dataRoot)
	require.NoError(t, err)

	sig, err := tbls.Sign(secret, signingRoot[:])
	require.NoError(t, err)

	return eth2p0.BLSSignature(sig)
}
