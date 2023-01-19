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

//nolint:gosec
package testutil

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/core/curves/native/bls12381"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/libp2p/go-libp2p"
	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/multiformats/go-multiaddr"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// RandomCorePubKey returns a random core workflow pubkey.
func RandomCorePubKey(t *testing.T) core.PubKey {
	t.Helper()
	random := rand.New(rand.NewSource(rand.Int63()))
	pubkey, _, err := tbls.KeygenWithSeed(random)
	require.NoError(t, err)
	resp, err := tblsconv.KeyToCore(pubkey)
	require.NoError(t, err)

	return resp
}

// RandomEth2PubKey returns a random eth2 phase0 bls pubkey.
func RandomEth2PubKey(t *testing.T) eth2p0.BLSPubKey {
	t.Helper()
	random := rand.New(rand.NewSource(rand.Int63()))
	pubkey, _, err := tbls.KeygenWithSeed(random)
	require.NoError(t, err)
	resp, err := tblsconv.KeyToETH2(pubkey)
	require.NoError(t, err)

	return resp
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

func RandomAttestation() *eth2p0.Attestation {
	return &eth2p0.Attestation{
		AggregationBits: RandomBitList(),
		Data:            RandomAttestationData(),
		Signature:       RandomEth2Signature(),
	}
}

func RandomAttestationData() *eth2p0.AttestationData {
	return &eth2p0.AttestationData{
		Slot:            RandomSlot(),
		Index:           RandomCommIdx(),
		BeaconBlockRoot: RandomRoot(),
		Source:          RandomCheckpoint(),
		Target:          RandomCheckpoint(),
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
		Graffiti:          RandomArray32(),
		ProposerSlashings: []*eth2p0.ProposerSlashing{},
		AttesterSlashings: []*eth2p0.AttesterSlashing{},
		Attestations:      []*eth2p0.Attestation{RandomAttestation(), RandomAttestation()},
		Deposits:          []*eth2p0.Deposit{},
		VoluntaryExits:    []*eth2p0.SignedVoluntaryExit{},
		SyncAggregate:     RandomSyncAggregate(),
		ExecutionPayload:  RandomCapellaExecutionPayload(),
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

func RandomBellatrixCoreVersionedBeaconBlock() core.VersionedBeaconBlock {
	return core.VersionedBeaconBlock{
		VersionedBeaconBlock: spec.VersionedBeaconBlock{
			Version:   spec.DataVersionBellatrix,
			Bellatrix: RandomBellatrixBeaconBlock(),
		},
	}
}

func RandomCapellaCoreVersionedBeaconBlock() core.VersionedBeaconBlock {
	return core.VersionedBeaconBlock{
		VersionedBeaconBlock: spec.VersionedBeaconBlock{
			Version: spec.DataVersionCapella,
			Capella: RandomCapellaBeaconBlock(),
		},
	}
}

func RandomBellatrixCoreVersionedSignedBeaconBlock() core.VersionedSignedBeaconBlock {
	return core.VersionedSignedBeaconBlock{
		VersionedSignedBeaconBlock: spec.VersionedSignedBeaconBlock{
			Version: spec.DataVersionBellatrix,
			Bellatrix: &bellatrix.SignedBeaconBlock{
				Message:   RandomBellatrixBeaconBlock(),
				Signature: RandomEth2Signature(),
			},
		},
	}
}

func RandomCapellaCoreVersionedSignedBeaconBlock() core.VersionedSignedBeaconBlock {
	return core.VersionedSignedBeaconBlock{
		VersionedSignedBeaconBlock: spec.VersionedSignedBeaconBlock{
			Version: spec.DataVersionCapella,
			Capella: &capella.SignedBeaconBlock{
				Message:   RandomCapellaBeaconBlock(),
				Signature: RandomEth2Signature(),
			},
		},
	}
}

// RandomCapellaVersionedSignedBeaconBlock returns a random signed capella beacon block.
func RandomCapellaVersionedSignedBeaconBlock() *spec.VersionedSignedBeaconBlock {
	return &spec.VersionedSignedBeaconBlock{
		Version: spec.DataVersionCapella,
		Capella: &capella.SignedBeaconBlock{
			Message:   RandomCapellaBeaconBlock(),
			Signature: RandomEth2Signature(),
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

func RandomBellatrixVersionedBlindedBeaconBlock() core.VersionedBlindedBeaconBlock {
	return core.VersionedBlindedBeaconBlock{
		VersionedBlindedBeaconBlock: eth2api.VersionedBlindedBeaconBlock{
			Version:   spec.DataVersionBellatrix,
			Bellatrix: RandomBellatrixBlindedBeaconBlock(),
		},
	}
}

func RandomCapellaVersionedBlindedBeaconBlock() core.VersionedBlindedBeaconBlock {
	return core.VersionedBlindedBeaconBlock{
		VersionedBlindedBeaconBlock: eth2api.VersionedBlindedBeaconBlock{
			Version: spec.DataVersionCapella,
			Capella: RandomCapellaBlindedBeaconBlock(),
		},
	}
}

func RandomBellatrixVersionedSignedBlindedBeaconBlock() core.VersionedSignedBlindedBeaconBlock {
	return core.VersionedSignedBlindedBeaconBlock{
		VersionedSignedBlindedBeaconBlock: eth2api.VersionedSignedBlindedBeaconBlock{
			Version: spec.DataVersionBellatrix,
			Bellatrix: &eth2bellatrix.SignedBlindedBeaconBlock{
				Message:   RandomBellatrixBlindedBeaconBlock(),
				Signature: RandomEth2Signature(),
			},
		},
	}
}

func RandomCapellaVersionedSignedBlindedBeaconBlock() core.VersionedSignedBlindedBeaconBlock {
	return core.VersionedSignedBlindedBeaconBlock{
		VersionedSignedBlindedBeaconBlock: eth2api.VersionedSignedBlindedBeaconBlock{
			Version: spec.DataVersionCapella,
			Capella: &eth2capella.SignedBlindedBeaconBlock{
				Message:   RandomCapellaBlindedBeaconBlock(),
				Signature: RandomEth2Signature(),
			},
		},
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
			Version: spec.BuilderVersionV1,
			V1:      RandomSignedValidatorRegistration(t),
		},
	}
}

func RandomVersionedSignedValidatorRegistration(t *testing.T) *eth2api.VersionedSignedValidatorRegistration {
	t.Helper()

	return &eth2api.VersionedSignedValidatorRegistration{
		Version: spec.BuilderVersionV1,
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
		Aggregate:       RandomAttestation(),
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
	_, _ = rand.Read(syncSSZ[:])
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

func RandomAttestationDuty(t *testing.T) *eth2v1.AttesterDuty {
	t.Helper()
	return &eth2v1.AttesterDuty{
		PubKey:                  RandomEth2PubKey(t),
		Slot:                    RandomSlot(),
		ValidatorIndex:          RandomVIdx(),
		CommitteeIndex:          RandomCommIdx(),
		CommitteeLength:         256,
		CommitteesAtSlot:        256,
		ValidatorCommitteeIndex: uint64(rand.Intn(256)),
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

func RandomRoot() eth2p0.Root {
	var resp eth2p0.Root
	_, _ = rand.Read(resp[:])

	return resp
}

func RandomBLSSignature() (*bls_sig.Signature, error) {
	g2, err := new(bls12381.G2).Random(crand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "random point in g2")
	}

	return &bls_sig.Signature{Value: *g2}, nil
}

func RandomEth2Signature() eth2p0.BLSSignature {
	var resp eth2p0.BLSSignature
	_, _ = rand.Read(resp[:])

	return resp
}

func RandomCoreSignature() core.Signature {
	resp := make(core.Signature, 96)
	_, _ = rand.Read(resp)

	return resp
}

func RandomCheckpoint() *eth2p0.Checkpoint {
	var resp eth2p0.Root
	_, _ = rand.Read(resp[:])

	return &eth2p0.Checkpoint{
		Epoch: RandomEpoch(),
		Root:  RandomRoot(),
	}
}

func RandomEpoch() eth2p0.Epoch {
	return eth2p0.Epoch(rand.Uint64())
}

func RandomSlot() eth2p0.Slot {
	return eth2p0.Slot(rand.Uint64())
}

func RandomCommIdx() eth2p0.CommitteeIndex {
	return eth2p0.CommitteeIndex(rand.Uint64())
}

func RandomVIdx() eth2p0.ValidatorIndex {
	return eth2p0.ValidatorIndex(rand.Uint64())
}

func RandomWithdrawalIdx() capella.WithdrawalIndex {
	return capella.WithdrawalIndex(rand.Uint64())
}

func RandomGwei() eth2p0.Gwei {
	return eth2p0.Gwei(rand.Uint64())
}

func RandomETHAddress() string {
	return fmt.Sprintf("%#x", RandomBytes32()[:20])
}

func RandomBytes20() []byte {
	return RandomBytes32()[:20]
}

func RandomBytes48() []byte {
	var resp [48]byte
	_, _ = rand.Read(resp[:])

	return resp[:]
}

func RandomBytes32() []byte {
	var resp [32]byte
	_, _ = rand.Read(resp[:])

	return resp[:]
}

func RandomArray32() [32]byte {
	var resp [32]byte
	_, _ = rand.Read(resp[:])

	return resp
}

func RandomBitList() bitfield.Bitlist {
	size := 256
	index := rand.Intn(size)
	resp := bitfield.NewBitlist(uint64(size))
	resp.SetBitAt(uint64(index), true)

	return resp
}

func RandomBitVec() bitfield.Bitvector128 {
	size := 128
	index := rand.Intn(size)
	resp := bitfield.NewBitvector128()
	resp.SetBitAt(uint64(index), true)

	return resp
}

// RandomSecp256k1Signature returns a random secp256k1 ECDSA signature with the last byte set to 0, 1, 27 or 28.
func RandomSecp256k1Signature() []byte {
	var resp [65]byte
	_, _ = rand.Read(resp[:])

	r1 := resp[0] % 2        // 0 or 1
	r2 := 27 * (resp[1] % 2) // 0 or 27
	lastByte := r1 + r2      // 0, 1, 27 or 28
	resp[64] = lastByte

	return resp[:]
}

func RandomExecutionAddress() bellatrix.ExecutionAddress {
	var resp [20]byte
	_, _ = rand.Read(resp[:])

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
	pkey, _, err := p2pcrypto.GenerateSecp256k1Key(crand.Reader)
	require.NoError(t, err)

	addrs, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", addr.IP, addr.Port))
	require.NoError(t, err)

	opts2 := []libp2p.Option{libp2p.Identity(pkey), libp2p.ListenAddrs(addrs)}
	opts2 = append(opts2, opts...)

	h, err := libp2p.New(opts2...)

	require.NoError(t, err)

	return h
}

func RandomENR(t *testing.T, random io.Reader) (*ecdsa.PrivateKey, enr.Record) {
	t.Helper()

	p2pKey, err := ecdsa.GenerateKey(crypto.S256(), random)
	require.NoError(t, err)

	var r enr.Record
	err = enode.SignV4(&r, p2pKey)
	require.NoError(t, err)

	return p2pKey, r
}

func RandomCoreAttestationData(t *testing.T) core.AttestationData {
	t.Helper()

	duty := RandomAttestationDuty(t)
	data := RandomAttestationData()

	return core.AttestationData{
		Data: *data,
		Duty: *duty,
	}
}

func RandomUnsignedDataSet(t *testing.T) core.UnsignedDataSet {
	t.Helper()

	return core.UnsignedDataSet{
		RandomCorePubKey(t): RandomCoreAttestationData(t),
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

// RandomHex32 returns a random 32 character hex string.
func RandomHex32() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", errors.Wrap(err, "read random")
	}

	return hex.EncodeToString(b), nil
}
