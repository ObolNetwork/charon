// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

//nolint:gosec
package testutil

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"fmt"
	"math"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/holiman/uint256"
	"github.com/libp2p/go-libp2p"
	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/multiformats/go-multiaddr"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/tbls"
)

func deterministicPubkeySeed(t *testing.T, r *rand.Rand) tbls.PublicKey {
	t.Helper()
	random := rand.New(rand.NewSource(r.Int63()))

	var key tbls.PublicKey
	_, err := random.Read(key[:])
	require.NoError(t, err)

	return key
}

func NewSeedRand() *rand.Rand {
	return rand.New(rand.NewSource(rand.Int63()))
}

// RandomCorePubKey returns a random core workflow pubkey.
func RandomCorePubKey(t *testing.T) core.PubKey {
	t.Helper()
	return RandomCorePubKeySeed(t, NewSeedRand())
}

func RandomCorePubKeySeed(t *testing.T, r *rand.Rand) core.PubKey {
	t.Helper()
	pubkey := deterministicPubkeySeed(t, r)
	resp, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)

	return resp
}

// RandomEth2PubKey returns a random eth2 phase0 bls pubkey.
func RandomEth2PubKey(t *testing.T) eth2p0.BLSPubKey {
	t.Helper()
	return RandomEth2PubKeySeed(t, NewSeedRand())
}

func RandomEth2PubKeySeed(t *testing.T, r *rand.Rand) eth2p0.BLSPubKey {
	t.Helper()
	pubkey := deterministicPubkeySeed(t, r)

	return eth2p0.BLSPubKey(pubkey)
}

func RandomValidator(t *testing.T) *eth2v1.Validator {
	t.Helper()

	return &eth2v1.Validator{
		Index:   eth2p0.ValidatorIndex(rand.Uint64()),
		Balance: RandomGwei(),
		Status:  eth2v1.ValidatorStateActiveOngoing,
		Validator: &eth2p0.Validator{
			PublicKey:                  RandomEth2PubKey(t),
			WithdrawalCredentials:      RandomBytes32(),
			EffectiveBalance:           RandomGwei(),
			Slashed:                    false,
			ActivationEligibilityEpoch: 1,
			ActivationEpoch:            2,
			ExitEpoch:                  0,
			WithdrawableEpoch:          3,
		},
	}
}

func RandomValidatorSet(t *testing.T, vals int) map[eth2p0.ValidatorIndex]*eth2v1.Validator {
	t.Helper()

	resp := make(map[eth2p0.ValidatorIndex]*eth2v1.Validator)
	for i := 0; i < vals; i++ {
		val := RandomValidator(t)
		resp[val.Index] = val
	}

	return resp
}

func RandomAttestation() *eth2p0.Attestation {
	return &eth2p0.Attestation{
		AggregationBits: RandomBitList(1),
		Data:            RandomAttestationData(),
		Signature:       RandomEth2Signature(),
	}
}

func RandomAggregateAttestation() *eth2p0.Attestation {
	return &eth2p0.Attestation{
		AggregationBits: RandomBitList(64),
		Data:            RandomAttestationData(),
		Signature:       RandomEth2Signature(),
	}
}

func RandomAttestationData() *eth2p0.AttestationData {
	return RandomAttestationDataSeed(NewSeedRand())
}

func RandomAttestationDataSeed(r *rand.Rand) *eth2p0.AttestationData {
	return &eth2p0.AttestationData{
		Slot:            RandomSlotSeed(r),
		Index:           RandomCommIdxSeed(r),
		BeaconBlockRoot: RandomRootSeed(r),
		Source:          RandomCheckpointSeed(r),
		Target:          RandomCheckpointSeed(r),
	}
}

func RandomPhase0BeaconBlock() *eth2p0.BeaconBlock {
	return &eth2p0.BeaconBlock{
		Slot:          RandomSlot(),
		ProposerIndex: RandomVIdx(),
		ParentRoot:    RandomRoot(),
		StateRoot:     RandomRoot(),
		Body:          RandomPhase0BeaconBlockBody(),
	}
}

func RandomPhase0BeaconBlockBody() *eth2p0.BeaconBlockBody {
	return &eth2p0.BeaconBlockBody{
		RANDAOReveal: RandomEth2Signature(),
		ETH1Data: &eth2p0.ETH1Data{
			DepositRoot:  RandomRoot(),
			DepositCount: 0,
			BlockHash:    RandomBytes32(),
		},
		Graffiti:          RandomArray32(),
		ProposerSlashings: []*eth2p0.ProposerSlashing{},
		AttesterSlashings: []*eth2p0.AttesterSlashing{},
		Attestations:      []*eth2p0.Attestation{RandomAttestation(), RandomAttestation()},
		Deposits:          []*eth2p0.Deposit{},
		VoluntaryExits:    []*eth2p0.SignedVoluntaryExit{},
	}
}

func RandomAltairBeaconBlock() *altair.BeaconBlock {
	return &altair.BeaconBlock{
		Slot:          RandomSlot(),
		ProposerIndex: RandomVIdx(),
		ParentRoot:    RandomRoot(),
		StateRoot:     RandomRoot(),
		Body:          RandomAltairBeaconBlockBody(),
	}
}

func RandomAltairBeaconBlockBody() *altair.BeaconBlockBody {
	return &altair.BeaconBlockBody{
		RANDAOReveal: RandomEth2Signature(),
		ETH1Data: &eth2p0.ETH1Data{
			DepositRoot:  RandomRoot(),
			DepositCount: 0,
			BlockHash:    RandomBytes32(),
		},
		Graffiti:          RandomArray32(),
		ProposerSlashings: []*eth2p0.ProposerSlashing{},
		AttesterSlashings: []*eth2p0.AttesterSlashing{},
		Attestations:      []*eth2p0.Attestation{RandomAttestation(), RandomAttestation()},
		Deposits:          []*eth2p0.Deposit{},
		VoluntaryExits:    []*eth2p0.SignedVoluntaryExit{},
		SyncAggregate:     RandomSyncAggregate(),
	}
}

func RandomBellatrixBeaconBlock() *bellatrix.BeaconBlock {
	return &bellatrix.BeaconBlock{
		Slot:          RandomSlot(),
		ProposerIndex: RandomVIdx(),
		ParentRoot:    RandomRoot(),
		StateRoot:     RandomRoot(),
		Body:          RandomBellatrixBeaconBlockBody(),
	}
}

func RandomBellatrixSignedBeaconBlock() *bellatrix.SignedBeaconBlock {
	return &bellatrix.SignedBeaconBlock{
		Message:   RandomBellatrixBeaconBlock(),
		Signature: RandomEth2Signature(),
	}
}

func RandomBellatrixBeaconBlockBody() *bellatrix.BeaconBlockBody {
	return &bellatrix.BeaconBlockBody{
		RANDAOReveal: RandomEth2Signature(),
		ETH1Data: &eth2p0.ETH1Data{
			DepositRoot:  RandomRoot(),
			DepositCount: 0,
			BlockHash:    RandomBytes32(),
		},
		Graffiti:          RandomArray32(),
		ProposerSlashings: []*eth2p0.ProposerSlashing{},
		AttesterSlashings: []*eth2p0.AttesterSlashing{},
		Attestations:      []*eth2p0.Attestation{RandomAttestation(), RandomAttestation()},
		Deposits:          []*eth2p0.Deposit{},
		VoluntaryExits:    []*eth2p0.SignedVoluntaryExit{},
		SyncAggregate:     RandomSyncAggregate(),
		ExecutionPayload:  RandomBellatrixExecutionPayLoad(),
	}
}

func RandomCapellaBeaconBlock() *capella.BeaconBlock {
	return &capella.BeaconBlock{
		Slot: RandomSlot(),
		Body: RandomCapellaBeaconBlockBody(),
	}
}

func RandomCapellaBeaconBlockBody() *capella.BeaconBlockBody {
	return &capella.BeaconBlockBody{
		RANDAOReveal: RandomEth2Signature(),
		ETH1Data: &eth2p0.ETH1Data{
			DepositRoot:  RandomRoot(),
			DepositCount: 0,
			BlockHash:    RandomBytes32(),
		},
		Graffiti:              RandomArray32(),
		ProposerSlashings:     []*eth2p0.ProposerSlashing{},
		AttesterSlashings:     []*eth2p0.AttesterSlashing{},
		Attestations:          []*eth2p0.Attestation{RandomAttestation(), RandomAttestation()},
		Deposits:              []*eth2p0.Deposit{},
		VoluntaryExits:        []*eth2p0.SignedVoluntaryExit{},
		SyncAggregate:         RandomSyncAggregate(),
		ExecutionPayload:      RandomCapellaExecutionPayload(),
		BLSToExecutionChanges: []*capella.SignedBLSToExecutionChange{},
	}
}

func RandomCapellaExecutionPayload() *capella.ExecutionPayload {
	return &capella.ExecutionPayload{
		ParentHash:    RandomArray32(),
		StateRoot:     RandomArray32(),
		ReceiptsRoot:  RandomArray32(),
		PrevRandao:    RandomArray32(),
		ExtraData:     RandomBytes32(),
		BaseFeePerGas: RandomArray32(),
		BlockHash:     RandomArray32(),
		Transactions:  []bellatrix.Transaction{},
		Withdrawals:   RandomWithdrawals(),
	}
}

func RandomBellatrixCoreVersionedProposal() core.VersionedProposal {
	return core.VersionedProposal{
		VersionedProposal: eth2api.VersionedProposal{
			Version:   eth2spec.DataVersionBellatrix,
			Bellatrix: RandomBellatrixBeaconBlock(),
		},
	}
}

func RandomCapellaCoreVersionedProposal() core.VersionedProposal {
	return core.VersionedProposal{
		VersionedProposal: eth2api.VersionedProposal{
			Version: eth2spec.DataVersionCapella,
			Capella: RandomCapellaBeaconBlock(),
		},
	}
}

func RandomBellatrixCoreVersionedSignedProposal() core.VersionedSignedProposal {
	return core.VersionedSignedProposal{
		VersionedSignedProposal: eth2api.VersionedSignedProposal{
			Version: eth2spec.DataVersionBellatrix,
			Bellatrix: &bellatrix.SignedBeaconBlock{
				Message:   RandomBellatrixBeaconBlock(),
				Signature: RandomEth2Signature(),
			},
		},
	}
}

func RandomCapellaCoreVersionedSignedProposal() core.VersionedSignedProposal {
	return core.VersionedSignedProposal{
		VersionedSignedProposal: eth2api.VersionedSignedProposal{
			Version: eth2spec.DataVersionCapella,
			Capella: &capella.SignedBeaconBlock{
				Message:   RandomCapellaBeaconBlock(),
				Signature: RandomEth2Signature(),
			},
		},
	}
}

func RandomDenebCoreVersionedSignedProposal() core.VersionedSignedProposal {
	return core.VersionedSignedProposal{
		VersionedSignedProposal: eth2api.VersionedSignedProposal{
			Version: eth2spec.DataVersionDeneb,
			Deneb: &eth2deneb.SignedBlockContents{
				SignedBlock: &deneb.SignedBeaconBlock{
					Message:   RandomDenebBeaconBlock(),
					Signature: RandomEth2Signature(),
				},
				KZGProofs: []deneb.KZGProof{},
				Blobs:     []deneb.Blob{},
			},
		},
	}
}

// RandomCapellaVersionedSignedBeaconBlock returns a random signed capella beacon block.
func RandomCapellaVersionedSignedBeaconBlock() *eth2spec.VersionedSignedBeaconBlock {
	return &eth2spec.VersionedSignedBeaconBlock{
		Version: eth2spec.DataVersionCapella,
		Capella: &capella.SignedBeaconBlock{
			Message:   RandomCapellaBeaconBlock(),
			Signature: RandomEth2Signature(),
		},
	}
}

// RandomDenebVersionedSignedBeaconBlock returns a random signed deneb beacon block.
func RandomDenebVersionedSignedBeaconBlock() *eth2spec.VersionedSignedBeaconBlock {
	return &eth2spec.VersionedSignedBeaconBlock{
		Version: eth2spec.DataVersionDeneb,
		Deneb: &deneb.SignedBeaconBlock{
			Message:   RandomDenebBeaconBlock(),
			Signature: RandomEth2Signature(),
		},
	}
}

// RandomCapellaVersionedSignedProposal returns a random versioned signed proposal containing capella beacon block.
func RandomCapellaVersionedSignedProposal() *eth2api.VersionedSignedProposal {
	return &eth2api.VersionedSignedProposal{
		Version: eth2spec.DataVersionCapella,
		Capella: &capella.SignedBeaconBlock{
			Message:   RandomCapellaBeaconBlock(),
			Signature: RandomEth2Signature(),
		},
	}
}

// RandomDenebVersionedSignedProposal returns a random versioned signed proposal containing deneb beacon block.
func RandomDenebVersionedSignedProposal() *eth2api.VersionedSignedProposal {
	return &eth2api.VersionedSignedProposal{
		Version: eth2spec.DataVersionDeneb,
		Deneb: &eth2deneb.SignedBlockContents{
			SignedBlock: &deneb.SignedBeaconBlock{
				Message:   RandomDenebBeaconBlock(),
				Signature: RandomEth2Signature(),
			},
			KZGProofs: []deneb.KZGProof{},
			Blobs:     []deneb.Blob{},
		},
	}
}

// RandomCapellaVersionedProposal returns a random versioned proposal containing capella beacon block.
func RandomCapellaVersionedProposal() *eth2api.VersionedProposal {
	return &eth2api.VersionedProposal{
		Version: eth2spec.DataVersionCapella,
		Capella: RandomCapellaBeaconBlock(),
	}
}

// RandomDenebVersionedProposal returns a random versioned proposal containing deneb beacon block.
func RandomDenebVersionedProposal() *eth2api.VersionedProposal {
	return &eth2api.VersionedProposal{
		Version: eth2spec.DataVersionDeneb,
		Deneb: &eth2deneb.BlockContents{
			Block:     RandomDenebBeaconBlock(),
			KZGProofs: []deneb.KZGProof{},
			Blobs:     []deneb.Blob{},
		},
	}
}

func RandomBellatrixBlindedBeaconBlock() *eth2bellatrix.BlindedBeaconBlock {
	return &eth2bellatrix.BlindedBeaconBlock{
		Slot:          RandomSlot(),
		ProposerIndex: RandomVIdx(),
		ParentRoot:    RandomRoot(),
		StateRoot:     RandomRoot(),
		Body:          RandomBellatrixBlindedBeaconBlockBody(),
	}
}

func RandomBellatrixBlindedBeaconBlockBody() *eth2bellatrix.BlindedBeaconBlockBody {
	return &eth2bellatrix.BlindedBeaconBlockBody{
		RANDAOReveal: RandomEth2Signature(),
		ETH1Data: &eth2p0.ETH1Data{
			DepositRoot:  RandomRoot(),
			DepositCount: 0,
			BlockHash:    RandomBytes32(),
		},
		Graffiti:               RandomArray32(),
		ProposerSlashings:      []*eth2p0.ProposerSlashing{},
		AttesterSlashings:      []*eth2p0.AttesterSlashing{},
		Attestations:           []*eth2p0.Attestation{RandomAttestation(), RandomAttestation()},
		Deposits:               []*eth2p0.Deposit{},
		VoluntaryExits:         []*eth2p0.SignedVoluntaryExit{},
		SyncAggregate:          RandomSyncAggregate(),
		ExecutionPayloadHeader: RandomBellatrixExecutionPayloadHeader(),
	}
}

func RandomCapellaBlindedBeaconBlock() *eth2capella.BlindedBeaconBlock {
	return &eth2capella.BlindedBeaconBlock{
		Slot:          RandomSlot(),
		ProposerIndex: RandomVIdx(),
		ParentRoot:    RandomRoot(),
		StateRoot:     RandomRoot(),
		Body:          RandomCapellaBlindedBeaconBlockBody(),
	}
}

func RandomCapellaBlindedBeaconBlockBody() *eth2capella.BlindedBeaconBlockBody {
	return &eth2capella.BlindedBeaconBlockBody{
		RANDAOReveal: RandomEth2Signature(),
		ETH1Data: &eth2p0.ETH1Data{
			DepositRoot:  RandomRoot(),
			DepositCount: 0,
			BlockHash:    RandomBytes32(),
		},
		Graffiti:               RandomArray32(),
		ProposerSlashings:      []*eth2p0.ProposerSlashing{},
		AttesterSlashings:      []*eth2p0.AttesterSlashing{},
		Attestations:           []*eth2p0.Attestation{RandomAttestation(), RandomAttestation()},
		Deposits:               []*eth2p0.Deposit{},
		VoluntaryExits:         []*eth2p0.SignedVoluntaryExit{},
		SyncAggregate:          RandomSyncAggregate(),
		ExecutionPayloadHeader: RandomCapellaExecutionPayloadHeader(),
		BLSToExecutionChanges:  []*capella.SignedBLSToExecutionChange{},
	}
}

func RandomBellatrixVersionedBlindedProposal() core.VersionedProposal {
	return core.VersionedProposal{
		VersionedProposal: eth2api.VersionedProposal{
			Version:          eth2spec.DataVersionBellatrix,
			Blinded:          true,
			BellatrixBlinded: RandomBellatrixBlindedBeaconBlock(),
		},
	}
}

func RandomCapellaVersionedBlindedProposal() core.VersionedProposal {
	return core.VersionedProposal{
		VersionedProposal: eth2api.VersionedProposal{
			Version:        eth2spec.DataVersionCapella,
			Blinded:        true,
			CapellaBlinded: RandomCapellaBlindedBeaconBlock(),
		},
	}
}

func RandomBellatrixVersionedSignedBlindedProposal() core.VersionedSignedBlindedProposal {
	return core.VersionedSignedBlindedProposal{
		VersionedSignedBlindedProposal: eth2api.VersionedSignedBlindedProposal{
			Version: eth2spec.DataVersionBellatrix,
			Bellatrix: &eth2bellatrix.SignedBlindedBeaconBlock{
				Message:   RandomBellatrixBlindedBeaconBlock(),
				Signature: RandomEth2Signature(),
			},
		},
	}
}

func RandomCapellaVersionedSignedBlindedProposal() core.VersionedSignedBlindedProposal {
	return core.VersionedSignedBlindedProposal{
		VersionedSignedBlindedProposal: eth2api.VersionedSignedBlindedProposal{
			Version: eth2spec.DataVersionCapella,
			Capella: &eth2capella.SignedBlindedBeaconBlock{
				Message:   RandomCapellaBlindedBeaconBlock(),
				Signature: RandomEth2Signature(),
			},
		},
	}
}

func RandomDenebVersionedSignedBlindedProposal() core.VersionedSignedBlindedProposal {
	return core.VersionedSignedBlindedProposal{
		VersionedSignedBlindedProposal: eth2api.VersionedSignedBlindedProposal{
			Version: eth2spec.DataVersionDeneb,
			Deneb: &eth2deneb.SignedBlindedBeaconBlock{
				Message:   RandomDenebBlindedBeaconBlock(),
				Signature: RandomEth2Signature(),
			},
		},
	}
}

func RandomDenebBeaconBlock() *deneb.BeaconBlock {
	return &deneb.BeaconBlock{
		Slot:          RandomSlot(),
		ProposerIndex: RandomVIdx(),
		ParentRoot:    RandomRoot(),
		StateRoot:     RandomRoot(),
		Body:          RandomDenebBeaconBlockBody(),
	}
}

func RandomDenebBlindedBeaconBlock() *eth2deneb.BlindedBeaconBlock {
	return &eth2deneb.BlindedBeaconBlock{
		Slot:          RandomSlot(),
		ProposerIndex: RandomVIdx(),
		ParentRoot:    RandomRoot(),
		StateRoot:     RandomRoot(),
		Body:          RandomDenebBlindedBeaconBlockBody(),
	}
}

func RandomDenebBeaconBlockBody() *deneb.BeaconBlockBody {
	return &deneb.BeaconBlockBody{
		RANDAOReveal: RandomEth2Signature(),
		ETH1Data: &eth2p0.ETH1Data{
			DepositRoot:  RandomRoot(),
			DepositCount: 0,
			BlockHash:    RandomBytes32(),
		},
		Graffiti:              RandomArray32(),
		ProposerSlashings:     []*eth2p0.ProposerSlashing{},
		AttesterSlashings:     []*eth2p0.AttesterSlashing{},
		Attestations:          []*eth2p0.Attestation{RandomAttestation(), RandomAttestation()},
		Deposits:              []*eth2p0.Deposit{},
		VoluntaryExits:        []*eth2p0.SignedVoluntaryExit{},
		SyncAggregate:         RandomSyncAggregate(),
		ExecutionPayload:      RandomDenebExecutionPayload(),
		BLSToExecutionChanges: []*capella.SignedBLSToExecutionChange{},
		BlobKZGCommitments:    []deneb.KZGCommitment{},
	}
}

func RandomDenebBlindedBeaconBlockBody() *eth2deneb.BlindedBeaconBlockBody {
	return &eth2deneb.BlindedBeaconBlockBody{
		RANDAOReveal: RandomEth2Signature(),
		ETH1Data: &eth2p0.ETH1Data{
			DepositRoot:  RandomRoot(),
			DepositCount: 0,
			BlockHash:    RandomBytes32(),
		},
		Graffiti:               RandomArray32(),
		ProposerSlashings:      []*eth2p0.ProposerSlashing{},
		AttesterSlashings:      []*eth2p0.AttesterSlashing{},
		Attestations:           []*eth2p0.Attestation{RandomAttestation(), RandomAttestation()},
		Deposits:               []*eth2p0.Deposit{},
		VoluntaryExits:         []*eth2p0.SignedVoluntaryExit{},
		SyncAggregate:          RandomSyncAggregate(),
		ExecutionPayloadHeader: RandomDenebExecutionPayloadHeader(),
		BLSToExecutionChanges:  []*capella.SignedBLSToExecutionChange{},
		BlobKZGCommitments:     []deneb.KZGCommitment{},
	}
}

func RandomValidatorRegistration(t *testing.T) *eth2v1.ValidatorRegistration {
	t.Helper()

	return &eth2v1.ValidatorRegistration{
		GasLimit:  rand.Uint64(),
		Pubkey:    RandomEth2PubKey(t),
		Timestamp: time.Unix(0, 0),
	}
}

func RandomSignedValidatorRegistration(t *testing.T) *eth2v1.SignedValidatorRegistration {
	t.Helper()

	return &eth2v1.SignedValidatorRegistration{
		Message: &eth2v1.ValidatorRegistration{
			FeeRecipient: RandomExecutionAddress(),
			GasLimit:     rand.Uint64(),
			Timestamp:    time.Now().Truncate(time.Second), // Serialised via unix seconds.
			Pubkey:       RandomEth2PubKey(t),
		},
		Signature: RandomEth2Signature(),
	}
}

func RandomCoreVersionedSignedValidatorRegistration(t *testing.T) core.VersionedSignedValidatorRegistration {
	t.Helper()

	return core.VersionedSignedValidatorRegistration{
		VersionedSignedValidatorRegistration: eth2api.VersionedSignedValidatorRegistration{
			Version: eth2spec.BuilderVersionV1,
			V1:      RandomSignedValidatorRegistration(t),
		},
	}
}

func RandomVersionedSignedValidatorRegistration(t *testing.T) *eth2api.VersionedSignedValidatorRegistration {
	t.Helper()

	return &eth2api.VersionedSignedValidatorRegistration{
		Version: eth2spec.BuilderVersionV1,
		V1:      RandomSignedValidatorRegistration(t),
	}
}

func RandomBeaconCommitteeSelection() *eth2exp.BeaconCommitteeSelection {
	return &eth2exp.BeaconCommitteeSelection{
		ValidatorIndex: RandomVIdx(),
		Slot:           RandomSlot(),
		SelectionProof: RandomEth2Signature(),
	}
}

func RandomCoreBeaconCommitteeSelection() core.BeaconCommitteeSelection {
	return core.NewBeaconCommitteeSelection(RandomBeaconCommitteeSelection())
}

func RandomCoreSyncCommitteeSelection() core.SyncCommitteeSelection {
	return core.NewSyncCommitteeSelection(RandomSyncCommitteeSelection())
}

func RandomSignedAggregateAndProof() *eth2p0.SignedAggregateAndProof {
	return &eth2p0.SignedAggregateAndProof{
		Message:   RandomAggregateAndProof(),
		Signature: RandomEth2Signature(),
	}
}

func RandomAggregateAndProof() *eth2p0.AggregateAndProof {
	return &eth2p0.AggregateAndProof{
		AggregatorIndex: RandomVIdx(),
		Aggregate:       RandomAggregateAttestation(),
		SelectionProof:  RandomEth2Signature(),
	}
}

func RandomSignedSyncContributionAndProof() *altair.SignedContributionAndProof {
	return &altair.SignedContributionAndProof{
		Message:   RandomSyncContributionAndProof(),
		Signature: RandomEth2Signature(),
	}
}

func RandomCoreSignedSyncContributionAndProof() core.SignedSyncContributionAndProof {
	return core.SignedSyncContributionAndProof{SignedContributionAndProof: *RandomSignedSyncContributionAndProof()}
}

func RandomCoreSyncContribution() core.SyncContribution {
	return core.SyncContribution{SyncCommitteeContribution: *RandomSyncCommitteeContribution()}
}

func RandomSyncContributionAndProof() *altair.ContributionAndProof {
	return &altair.ContributionAndProof{
		AggregatorIndex: RandomVIdx(),
		Contribution:    RandomSyncCommitteeContribution(),
		SelectionProof:  RandomEth2Signature(),
	}
}

func RandomSyncCommitteeContribution() *altair.SyncCommitteeContribution {
	return &altair.SyncCommitteeContribution{
		Slot:              RandomSlot(),
		BeaconBlockRoot:   RandomRoot(),
		SubcommitteeIndex: rand.Uint64(),
		AggregationBits:   RandomBitVec(),
		Signature:         RandomEth2Signature(),
	}
}

func RandomSyncCommitteeMessage() *altair.SyncCommitteeMessage {
	return &altair.SyncCommitteeMessage{
		Slot:            RandomSlot(),
		BeaconBlockRoot: RandomRoot(),
		ValidatorIndex:  RandomVIdx(),
		Signature:       RandomEth2Signature(),
	}
}

func RandomSyncCommittee(t *testing.T) *altair.SyncCommittee {
	t.Helper()

	var pubkeys []eth2p0.BLSPubKey
	for i := 0; i < 512; i++ {
		pubkeys = append(pubkeys, RandomEth2PubKey(t))
	}

	return &altair.SyncCommittee{
		Pubkeys:         pubkeys,
		AggregatePubkey: RandomEth2PubKey(t),
	}
}

func RandomSyncCommitteeSelection() *eth2exp.SyncCommitteeSelection {
	return &eth2exp.SyncCommitteeSelection{
		ValidatorIndex:    RandomVIdx(),
		Slot:              RandomSlot(),
		SubcommitteeIndex: RandomCommIdx(),
		SelectionProof:    RandomEth2Signature(),
	}
}

func RandomSyncCommitteeDuty(t *testing.T) *eth2v1.SyncCommitteeDuty {
	t.Helper()

	return &eth2v1.SyncCommitteeDuty{
		PubKey:                        RandomEth2PubKey(t),
		ValidatorIndex:                RandomVIdx(),
		ValidatorSyncCommitteeIndices: []eth2p0.CommitteeIndex{RandomCommIdx()},
	}
}

func RandomSyncAggregate() *altair.SyncAggregate {
	var syncSSZ [160]byte
	_, _ = crand.Read(syncSSZ[:])
	sync := new(altair.SyncAggregate)
	err := sync.UnmarshalSSZ(syncSSZ[:])
	if err != nil {
		panic(err) // Should never happen, and this is test code.
	}

	return sync
}

func RandomBellatrixExecutionPayLoad() *bellatrix.ExecutionPayload {
	return &bellatrix.ExecutionPayload{
		ParentHash:    RandomArray32(),
		StateRoot:     RandomArray32(),
		ReceiptsRoot:  RandomArray32(),
		PrevRandao:    RandomArray32(),
		ExtraData:     RandomBytes32(),
		BaseFeePerGas: RandomArray32(),
		BlockHash:     RandomArray32(),
		Transactions:  []bellatrix.Transaction{},
	}
}

func RandomWithdrawals() []*capella.Withdrawal {
	return []*capella.Withdrawal{
		{
			Index:          RandomWithdrawalIdx(),
			ValidatorIndex: RandomVIdx(),
			Address:        RandomExecutionAddress(),
			Amount:         RandomGwei(),
		},
	}
}

func RandomBellatrixExecutionPayloadHeader() *bellatrix.ExecutionPayloadHeader {
	return &bellatrix.ExecutionPayloadHeader{
		ParentHash:       RandomArray32(),
		StateRoot:        RandomArray32(),
		ReceiptsRoot:     RandomArray32(),
		PrevRandao:       RandomArray32(),
		ExtraData:        RandomBytes32(),
		BaseFeePerGas:    RandomArray32(),
		BlockHash:        RandomArray32(),
		TransactionsRoot: RandomArray32(),
	}
}

func RandomCapellaExecutionPayloadHeader() *capella.ExecutionPayloadHeader {
	return &capella.ExecutionPayloadHeader{
		ParentHash:       RandomArray32(),
		StateRoot:        RandomArray32(),
		ReceiptsRoot:     RandomArray32(),
		PrevRandao:       RandomArray32(),
		ExtraData:        RandomBytes32(),
		BaseFeePerGas:    RandomArray32(),
		BlockHash:        RandomArray32(),
		TransactionsRoot: RandomArray32(),
	}
}

func RandomDenebExecutionPayload() *deneb.ExecutionPayload {
	baseFeePerGas := new(uint256.Int)
	randBytes := RandomArray32()
	baseFeePerGas.SetBytes32(randBytes[:])

	return &deneb.ExecutionPayload{
		ParentHash:    RandomArray32(),
		StateRoot:     RandomArray32(),
		ReceiptsRoot:  RandomArray32(),
		LogsBloom:     [256]byte{},
		PrevRandao:    [32]byte{},
		ExtraData:     RandomBytes32(),
		BaseFeePerGas: baseFeePerGas,
		BlockHash:     RandomArray32(),
		Transactions:  []bellatrix.Transaction{},
		Withdrawals:   []*capella.Withdrawal{},
	}
}

func RandomDenebExecutionPayloadHeader() *deneb.ExecutionPayloadHeader {
	baseFeePerGas := new(uint256.Int)
	randBytes := RandomArray32()
	baseFeePerGas.SetBytes32(randBytes[:])

	return &deneb.ExecutionPayloadHeader{
		ParentHash:       RandomArray32(),
		StateRoot:        RandomArray32(),
		ReceiptsRoot:     RandomArray32(),
		PrevRandao:       RandomArray32(),
		BaseFeePerGas:    baseFeePerGas,
		ExtraData:        RandomBytes32(),
		BlockHash:        RandomArray32(),
		TransactionsRoot: RandomRoot(),
		WithdrawalsRoot:  RandomRoot(),
	}
}

func RandomAttestationDuty(t *testing.T) *eth2v1.AttesterDuty {
	t.Helper()
	return RandomAttestationDutySeed(t, NewSeedRand())
}

func RandomAttestationDutySeed(t *testing.T, r *rand.Rand) *eth2v1.AttesterDuty {
	t.Helper()
	return &eth2v1.AttesterDuty{
		PubKey:                  RandomEth2PubKeySeed(t, r),
		Slot:                    RandomSlotSeed(r),
		ValidatorIndex:          RandomVIdxSeed(r),
		CommitteeIndex:          RandomCommIdxSeed(r),
		CommitteeLength:         256,
		CommitteesAtSlot:        256,
		ValidatorCommitteeIndex: uint64(r.Intn(256)),
	}
}

func RandomProposerDuty(t *testing.T) *eth2v1.ProposerDuty {
	t.Helper()
	return &eth2v1.ProposerDuty{
		PubKey:         RandomEth2PubKey(t),
		Slot:           RandomSlot(),
		ValidatorIndex: RandomVIdx(),
	}
}

func RandomBeaconState(t *testing.T) *eth2spec.VersionedBeaconState {
	t.Helper()

	return &eth2spec.VersionedBeaconState{
		Version: eth2spec.DataVersionCapella,
		Capella: &capella.BeaconState{
			GenesisTime:           uint64(time.Now().Unix()),
			GenesisValidatorsRoot: RandomRoot(),
			Slot:                  RandomSlot(),
			Fork: &eth2p0.Fork{
				PreviousVersion: eth2p0.Version{},
				CurrentVersion:  eth2p0.Version{},
				Epoch:           0,
			},
			LatestBlockHeader: &eth2p0.BeaconBlockHeader{},
			BlockRoots:        []eth2p0.Root{RandomRoot()},
			StateRoots:        []eth2p0.Root{RandomRoot()},
			HistoricalRoots:   []eth2p0.Root{RandomRoot()},
			ETH1Data: &eth2p0.ETH1Data{
				DepositRoot:  RandomRoot(),
				DepositCount: 0,
				BlockHash:    RandomBytes32(),
			},
			// ETH1DataVotes:                nil,
			// ETH1DepositIndex:             0,
			Validators: []*eth2p0.Validator{
				RandomValidator(t).Validator,
				RandomValidator(t).Validator,
			},
			Balances: []eth2p0.Gwei{RandomGwei(), RandomGwei()},
			// RANDAOMixes:                  nil,
			// Slashings:                    nil,
			// PreviousEpochParticipation:   nil,
			// CurrentEpochParticipation:    nil,
			JustificationBits:           RandomBitVec4(),
			PreviousJustifiedCheckpoint: RandomCheckpoint(),
			CurrentJustifiedCheckpoint:  RandomCheckpoint(),
			FinalizedCheckpoint:         RandomCheckpoint(),
			// InactivityScores:             nil,
			CurrentSyncCommittee: RandomSyncCommittee(t),
			NextSyncCommittee:    RandomSyncCommittee(t),
			// LatestExecutionPayloadHeader: nil,
			// NextWithdrawalIndex:          0,
			// NextWithdrawalValidatorIndex: 0,
			HistoricalSummaries: []*capella.HistoricalSummary{RandomHistoricalSummary()},
		},
	}
}

func RandomHistoricalSummary() *capella.HistoricalSummary {
	return &capella.HistoricalSummary{
		BlockSummaryRoot: RandomRoot(),
		StateSummaryRoot: RandomRoot(),
	}
}

func RandomRoot() eth2p0.Root {
	return RandomRootSeed(NewSeedRand())
}

func RandomRootSeed(r *rand.Rand) eth2p0.Root {
	var resp eth2p0.Root
	_, _ = r.Read(resp[:])

	return resp
}

func RandomEth2Signature() eth2p0.BLSSignature {
	var resp eth2p0.BLSSignature
	_, _ = crand.Read(resp[:])

	return resp
}

func RandomEth2SignatureWithSeed(seed int64) eth2p0.BLSSignature {
	var resp eth2p0.BLSSignature
	_, _ = rand.New(rand.NewSource(seed)).Read(resp[:])

	return resp
}

func RandomCoreSignature() core.Signature {
	resp := make(core.Signature, 96)
	_, _ = crand.Read(resp)

	return resp
}

func RandomCheckpoint() *eth2p0.Checkpoint {
	return RandomCheckpointSeed(NewSeedRand())
}

func RandomCheckpointSeed(r *rand.Rand) *eth2p0.Checkpoint {
	var resp eth2p0.Root
	_, _ = r.Read(resp[:])

	return &eth2p0.Checkpoint{
		Epoch: RandomEpochSeed(r),
		Root:  RandomRootSeed(r),
	}
}

func RandomEpoch() eth2p0.Epoch {
	return RandomEpochSeed(NewSeedRand())
}

func RandomEpochSeed(r *rand.Rand) eth2p0.Epoch {
	return eth2p0.Epoch(r.Int63n(int64(math.Pow(2, 53))))
}

func RandomSlot() eth2p0.Slot {
	return RandomSlotSeed(NewSeedRand())
}

func RandomSlotSeed(r *rand.Rand) eth2p0.Slot {
	return eth2p0.Slot(r.Int63n(int64(math.Pow(2, 53))))
}

func RandomCommIdx() eth2p0.CommitteeIndex {
	return RandomCommIdxSeed(NewSeedRand())
}

func RandomCommIdxSeed(r *rand.Rand) eth2p0.CommitteeIndex {
	return eth2p0.CommitteeIndex(r.Int63n(int64(math.Pow(2, 53))))
}

func RandomVIdx() eth2p0.ValidatorIndex {
	return RandomVIdxSeed(NewSeedRand())
}

func RandomVIdxSeed(r *rand.Rand) eth2p0.ValidatorIndex {
	return eth2p0.ValidatorIndex(r.Int63n(int64(math.Pow(2, 53))))
}

func RandomWithdrawalIdx() capella.WithdrawalIndex {
	return capella.WithdrawalIndex(rand.Int63n(int64(math.Pow(2, 53))))
}

func RandomGwei() eth2p0.Gwei {
	return eth2p0.Gwei(rand.Int63n(int64(math.Pow(2, 53))))
}

func RandomETHAddress() string {
	return RandomETHAddressSeed(NewSeedRand())
}

func RandomETHAddressSeed(r *rand.Rand) string {
	return fmt.Sprintf("%#x", RandomBytes32Seed(r)[:20])
}

func RandomChecksummedETHAddress(t *testing.T, seed int) string {
	t.Helper()

	// Generate a new random private key
	privatekey := GenerateInsecureK1Key(t, seed)

	// Get the corresponding public key
	publicKey := privatekey.PubKey()

	// Derive the Ethereum address from the public key
	return eth2util.PublicKeyToAddress(publicKey)
}

func RandomBytes96() []byte {
	return RandomBytes96Seed(NewSeedRand())
}

func RandomBytes96Seed(r *rand.Rand) []byte {
	var resp [96]byte
	_, _ = r.Read(resp[:])

	return resp[:]
}

func RandomBytes48() []byte {
	return RandomBytes48Seed(NewSeedRand())
}

func RandomBytes48Seed(r *rand.Rand) []byte {
	var resp [48]byte
	_, _ = r.Read(resp[:])

	return resp[:]
}

func RandomBytes32() []byte {
	return RandomBytes32Seed(NewSeedRand())
}

func RandomBytes32Seed(r *rand.Rand) []byte {
	var resp [32]byte
	_, _ = r.Read(resp[:])

	return resp[:]
}

func RandomArray32() [32]byte {
	return RandomArray32Seed(NewSeedRand())
}

func RandomArray32Seed(r *rand.Rand) [32]byte {
	var resp [32]byte
	_, _ = r.Read(resp[:])

	return resp
}

func RandomBitList(length int) bitfield.Bitlist {
	size := 256
	resp := bitfield.NewBitlist(uint64(size))
	for i := 0; i < length; i++ {
		resp.SetBitAt(uint64(rand.Intn(size)), true)
	}

	return resp
}

func RandomBitVec() bitfield.Bitvector128 {
	size := 128
	index := rand.Intn(size)
	resp := bitfield.NewBitvector128()
	resp.SetBitAt(uint64(index), true)

	return resp
}

func RandomBitVec4() bitfield.Bitvector4 {
	size := 4
	index := rand.Intn(size)
	resp := bitfield.NewBitvector4()
	resp.SetBitAt(uint64(index), true)

	return resp
}

// RandomSecp256k1Signature returns a random byte slice of length 65 with the last byte set to 0, 1, 27 or 28.
func RandomSecp256k1Signature() []byte {
	return RandomSecp256k1SignatureSeed(NewSeedRand())
}

func RandomSecp256k1SignatureSeed(r *rand.Rand) []byte {
	var resp [65]byte
	_, _ = r.Read(resp[:])

	r1 := resp[0] % 2        // 0 or 1
	r2 := 27 * (resp[1] % 2) // 0 or 27
	lastByte := r1 + r2      // 0, 1, 27 or 28
	resp[64] = lastByte

	return resp[:]
}

func RandomExecutionAddress() bellatrix.ExecutionAddress {
	var resp [20]byte
	_, _ = crand.Read(resp[:])

	return resp
}

// SkipIfBindErr skips the test if the error is "bind: address already in use".
// This is a workaround for the issue related to AvailableAddr.
func SkipIfBindErr(t *testing.T, err error) {
	t.Helper()

	if err != nil && strings.Contains(err.Error(), "bind: address already in use") {
		t.Skip("Skipping test as workaround to sporadic port bind issue")
	}
}

// AvailableAddr returns an available local tcp address.
//
// Note that this is unfortunately only best-effort. Since the port is not
// "locked" or "reserved", other processes sometimes grab the port.
// Remember to call SkipIfBindErr as workaround for this issue.
func AvailableAddr(t *testing.T) *net.TCPAddr {
	t.Helper()

	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	defer l.Close()

	addr, err := net.ResolveTCPAddr(l.Addr().Network(), l.Addr().String())
	require.NoError(t, err)

	return addr
}

// AvailableMultiAddr returns an available local tcp address as a multiaddr.
//
// Note that this is unfortunately only best-effort. Since the port is not
// "locked" or "reserved", other processes sometimes grab the port.
// Remember to call SkipIfBindErr as workaround for this issue.
func AvailableMultiAddr(t *testing.T) multiaddr.Multiaddr {
	t.Helper()

	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	defer l.Close()

	h, p, err := net.SplitHostPort(l.Addr().String())
	require.NoError(t, err)

	addr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%s", h, p))
	require.NoError(t, err)

	return addr
}

func CreateHost(t *testing.T, addr *net.TCPAddr, opts ...libp2p.Option) host.Host {
	t.Helper()
	pkey, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	return CreateHostWithIdentity(t, addr, pkey, opts...)
}

func CreateHostWithIdentity(t *testing.T, addr *net.TCPAddr, secret *k1.PrivateKey, opts ...libp2p.Option) host.Host {
	t.Helper()

	addrs, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", addr.IP, addr.Port))
	require.NoError(t, err)

	opts2 := []libp2p.Option{
		libp2p.Identity((*p2pcrypto.Secp256k1PrivateKey)(secret)),
		libp2p.ListenAddrs(addrs),
		libp2p.Transport(tcp.NewTCPTransport, tcp.DisableReuseport()),
	}
	opts2 = append(opts2, opts...)

	h, err := libp2p.New(opts2...)

	SkipIfBindErr(t, err)
	require.NoError(t, err)

	return h
}

func RandomENR(t *testing.T, seed int) (*k1.PrivateKey, enr.Record) {
	t.Helper()

	key := GenerateInsecureK1Key(t, seed)

	record, err := enr.New(key)
	require.NoError(t, err)

	return key, record
}

func RandomCoreAttestationData(t *testing.T) core.AttestationData {
	t.Helper()
	return RandomCoreAttestationDataSeed(t, NewSeedRand())
}

func RandomCoreAttestationDataSeed(t *testing.T, r *rand.Rand) core.AttestationData {
	t.Helper()

	duty := RandomAttestationDutySeed(t, r)
	data := RandomAttestationDataSeed(r)

	return core.AttestationData{
		Data: *data,
		Duty: *duty,
	}
}

func RandomUnsignedDataSet(t *testing.T) core.UnsignedDataSet {
	t.Helper()
	return RandomUnsignedDataSetSeed(t, NewSeedRand())
}

func RandomUnsignedDataSetSeed(t *testing.T, r *rand.Rand) core.UnsignedDataSet {
	t.Helper()

	return core.UnsignedDataSet{
		RandomCorePubKeySeed(t, r): RandomCoreAttestationDataSeed(t, r),
	}
}

func RandomExit() *eth2p0.SignedVoluntaryExit {
	return &eth2p0.SignedVoluntaryExit{
		Message: &eth2p0.VoluntaryExit{
			Epoch:          RandomEpoch(),
			ValidatorIndex: RandomVIdx(),
		},
		Signature: RandomEth2Signature(),
	}
}

func RandomCoreSignedRandao() core.SignedRandao {
	return core.SignedRandao{SignedEpoch: eth2util.SignedEpoch{
		Epoch:     RandomEpoch(),
		Signature: RandomEth2Signature(),
	}}
}

func RandomDepositMsg(t *testing.T) eth2p0.DepositMessage {
	t.Helper()

	return eth2p0.DepositMessage{
		PublicKey:             RandomEth2PubKey(t),
		WithdrawalCredentials: RandomBytes32(),
		Amount:                RandomGwei(),
	}
}

// constReader is a workaround. It counter-acts the Go library's attempt at
// making ECDSA signatures non-deterministic.
// Refer: https://cs.opensource.google/go/go/+/refs/tags/go1.20.2:src/crypto/ecdsa/ecdsa.go;l=155
type constReader byte

func (c constReader) Read(buf []byte) (int, error) {
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(c)
	}

	return len(buf), nil
}

// GenerateInsecureK1Key returns a new deterministic insecure secp256k1 private using the provided seed for testing purposes only.
// For random keys, rather use k1.GeneratePrivateKey().
func GenerateInsecureK1Key(t *testing.T, seed int) *k1.PrivateKey {
	t.Helper()

	// Add 1 to seed to avoid passing 0 as seed which can trigger infinite loop.
	k, err := ecdsa.GenerateKey(k1.S256(), constReader(seed+1))
	require.NoError(t, err)

	return k1.PrivKeyFromBytes(k.D.Bytes())
}

// RandomBool returns a random boolean.
func RandomBool() bool {
	return rand.Intn(2) == 0
}
