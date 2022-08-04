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
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/core/curves/native/bls12381"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/libp2p/go-libp2p"
	p2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/multiformats/go-multiaddr"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
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
		Graffiti:          RandomBytes32(),
		ProposerSlashings: []*eth2p0.ProposerSlashing{},
		AttesterSlashings: []*eth2p0.AttesterSlashing{},
		Attestations:      []*eth2p0.Attestation{RandomAttestation(), RandomAttestation()},
		Deposits:          []*eth2p0.Deposit{},
		VoluntaryExits:    []*eth2p0.SignedVoluntaryExit{},
	}
}

func RandomAltairBeaconBlock(t *testing.T) *altair.BeaconBlock {
	t.Helper()

	return &altair.BeaconBlock{
		Slot:          RandomSlot(),
		ProposerIndex: RandomVIdx(),
		ParentRoot:    RandomRoot(),
		StateRoot:     RandomRoot(),
		Body:          RandomAltairBeaconBlockBody(t),
	}
}

func RandomAltairBeaconBlockBody(t *testing.T) *altair.BeaconBlockBody {
	t.Helper()

	return &altair.BeaconBlockBody{
		RANDAOReveal: RandomEth2Signature(),
		ETH1Data: &eth2p0.ETH1Data{
			DepositRoot:  RandomRoot(),
			DepositCount: 0,
			BlockHash:    RandomBytes32(),
		},
		Graffiti:          RandomBytes32(),
		ProposerSlashings: []*eth2p0.ProposerSlashing{},
		AttesterSlashings: []*eth2p0.AttesterSlashing{},
		Attestations:      []*eth2p0.Attestation{RandomAttestation(), RandomAttestation()},
		Deposits:          []*eth2p0.Deposit{},
		VoluntaryExits:    []*eth2p0.SignedVoluntaryExit{},
		SyncAggregate:     RandomSyncAggregate(t),
	}
}

func RandomBellatrixBeaconBlock(t *testing.T) *bellatrix.BeaconBlock {
	t.Helper()

	return &bellatrix.BeaconBlock{
		Slot:          RandomSlot(),
		ProposerIndex: RandomVIdx(),
		ParentRoot:    RandomRoot(),
		StateRoot:     RandomRoot(),
		Body:          RandomBellatrixBeaconBlockBody(t),
	}
}

func RandomBellatrixBeaconBlockBody(t *testing.T) *bellatrix.BeaconBlockBody {
	t.Helper()

	return &bellatrix.BeaconBlockBody{
		RANDAOReveal: RandomEth2Signature(),
		ETH1Data: &eth2p0.ETH1Data{
			DepositRoot:  RandomRoot(),
			DepositCount: 0,
			BlockHash:    RandomBytes32(),
		},
		Graffiti:          RandomBytes32(),
		ProposerSlashings: []*eth2p0.ProposerSlashing{},
		AttesterSlashings: []*eth2p0.AttesterSlashing{},
		Attestations:      []*eth2p0.Attestation{RandomAttestation(), RandomAttestation()},
		Deposits:          []*eth2p0.Deposit{},
		VoluntaryExits:    []*eth2p0.SignedVoluntaryExit{},
		SyncAggregate:     RandomSyncAggregate(t),
		ExecutionPayload:  RandomExecutionPayLoad(),
	}
}

func RandomCoreVersionBeaconBlock(t *testing.T) core.VersionedBeaconBlock {
	t.Helper()

	return core.VersionedBeaconBlock{
		VersionedBeaconBlock: spec.VersionedBeaconBlock{
			Version:   spec.DataVersionBellatrix,
			Bellatrix: RandomBellatrixBeaconBlock(t),
		},
	}
}

func RandomCoreVersionSignedBeaconBlock(t *testing.T) core.VersionedSignedBeaconBlock {
	t.Helper()

	return core.VersionedSignedBeaconBlock{
		VersionedSignedBeaconBlock: spec.VersionedSignedBeaconBlock{
			Version: spec.DataVersionBellatrix,
			Bellatrix: &bellatrix.SignedBeaconBlock{
				Message:   RandomBellatrixBeaconBlock(t),
				Signature: RandomEth2Signature(),
			},
		},
	}
}

func RandomBellatrixBlindedBeaconBlock(t *testing.T) *eth2v1.BlindedBeaconBlock {
	t.Helper()

	return &eth2v1.BlindedBeaconBlock{
		Slot:          RandomSlot(),
		ProposerIndex: RandomVIdx(),
		ParentRoot:    RandomRoot(),
		StateRoot:     RandomRoot(),
		Body:          RandomBellatrixBlindedBeaconBlockBody(t),
	}
}

func RandomBellatrixBlindedBeaconBlockBody(t *testing.T) *eth2v1.BlindedBeaconBlockBody {
	t.Helper()

	return &eth2v1.BlindedBeaconBlockBody{
		RANDAOReveal: RandomEth2Signature(),
		ETH1Data: &eth2p0.ETH1Data{
			DepositRoot:  RandomRoot(),
			DepositCount: 0,
			BlockHash:    RandomBytes32(),
		},
		Graffiti:               RandomBytes32(),
		ProposerSlashings:      []*eth2p0.ProposerSlashing{},
		AttesterSlashings:      []*eth2p0.AttesterSlashing{},
		Attestations:           []*eth2p0.Attestation{RandomAttestation(), RandomAttestation()},
		Deposits:               []*eth2p0.Deposit{},
		VoluntaryExits:         []*eth2p0.SignedVoluntaryExit{},
		SyncAggregate:          RandomSyncAggregate(t),
		ExecutionPayloadHeader: RandomExecutionPayloadHeader(),
	}
}

func RandomCoreVersionBlindedBeaconBlock(t *testing.T) core.VersionedBlindedBeaconBlock {
	t.Helper()

	return core.VersionedBlindedBeaconBlock{
		VersionedBlindedBeaconBlock: eth2api.VersionedBlindedBeaconBlock{
			Version:   spec.DataVersionBellatrix,
			Bellatrix: RandomBellatrixBlindedBeaconBlock(t),
		},
	}
}

func RandomCoreVersionSignedBlindedBeaconBlock(t *testing.T) core.VersionedSignedBlindedBeaconBlock {
	t.Helper()

	return core.VersionedSignedBlindedBeaconBlock{
		VersionedSignedBlindedBeaconBlock: eth2api.VersionedSignedBlindedBeaconBlock{
			Version: spec.DataVersionBellatrix,
			Bellatrix: &eth2v1.SignedBlindedBeaconBlock{
				Message:   RandomBellatrixBlindedBeaconBlock(t),
				Signature: RandomEth2Signature(),
			},
		},
	}
}

func RandomValidatorRegistration(t *testing.T) *eth2v1.ValidatorRegistration {
	t.Helper()

	return &eth2v1.ValidatorRegistration{
		GasLimit: rand.Uint64(),
		Pubkey:   RandomEth2PubKey(t),
	}
}

func RandomSignedValidatorRegistration(t *testing.T) *eth2v1.SignedValidatorRegistration {
	t.Helper()

	return &eth2v1.SignedValidatorRegistration{
		Message: &eth2v1.ValidatorRegistration{
			FeeRecipient: bellatrix.ExecutionAddress{},
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

func RandomSyncAggregate(t *testing.T) *altair.SyncAggregate {
	t.Helper()

	var syncSSZ [160]byte
	_, _ = rand.Read(syncSSZ[:])
	sync := new(altair.SyncAggregate)
	err := sync.UnmarshalSSZ(syncSSZ[:])
	require.NoError(t, err)

	return sync
}

func RandomExecutionPayLoad() *bellatrix.ExecutionPayload {
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

func RandomExecutionPayloadHeader() *bellatrix.ExecutionPayloadHeader {
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

func RandomETHAddress() string {
	return fmt.Sprintf("%#x", RandomBytes32()[:20])
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

func CreateHost(t *testing.T, addr *net.TCPAddr) host.Host {
	t.Helper()
	pkey, _, err := p2pcrypto.GenerateSecp256k1Key(crand.Reader)
	require.NoError(t, err)

	addrs, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", addr.IP, addr.Port))
	require.NoError(t, err)

	h, err := libp2p.New(libp2p.Identity(pkey), libp2p.ListenAddrs(addrs))
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
