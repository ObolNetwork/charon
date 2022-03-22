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

//nolint:gosec
package testutil

import (
	crand "crypto/rand"
	"fmt"
	"math/rand"
	"net"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/multiformats/go-multiaddr"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// RandomPubKey returns a random core workflow pubkey.
func RandomPubKey(t *testing.T) core.PubKey {
	t.Helper()
	buf := make([]byte, 48)
	_, _ = rand.Read(buf)

	pubkey, err := core.PubKeyFromBytes(buf)
	require.NoError(t, err)

	return pubkey
}

// RandomBLSPubKey returns a random eth2 phase0 bls pubkey.
func RandomBLSPubKey(t *testing.T) eth2p0.BLSPubKey {
	t.Helper()
	pubkey, _, err := bls_sig.NewSigEth2().Keygen()
	require.NoError(t, err)
	resp, err := tblsconv.KeyToETH2(pubkey)
	require.NoError(t, err)

	return resp
}

func RandomAttestation() *eth2p0.Attestation {
	return &eth2p0.Attestation{
		AggregationBits: RandomBitList(),
		Data:            RandomAttestationData(),
		Signature:       RandomSignature(),
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

func RandomAttestationDuty(t *testing.T) *eth2v1.AttesterDuty {
	t.Helper()
	return &eth2v1.AttesterDuty{
		PubKey:                  RandomBLSPubKey(t),
		Slot:                    RandomSlot(),
		ValidatorIndex:          RandomVIdx(),
		CommitteeIndex:          RandomCommIdx(),
		CommitteeLength:         256,
		CommitteesAtSlot:        256,
		ValidatorCommitteeIndex: uint64(rand.Intn(256)),
	}
}

func RandomRoot() eth2p0.Root {
	var resp eth2p0.Root
	_, _ = rand.Read(resp[:])

	return resp
}

func RandomSignature() eth2p0.BLSSignature {
	var resp eth2p0.BLSSignature
	_, _ = rand.Read(resp[:])

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

func RandomBitList() bitfield.Bitlist {
	size := 256
	index := rand.Intn(size)
	resp := bitfield.NewBitlist(uint64(size))
	resp.SetBitAt(uint64(index), true)

	return resp
}

// AvailableAddr returns an available local tcp address.
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
	pkey, _, err := crypto.GenerateSecp256k1Key(crand.Reader)
	require.NoError(t, err)

	addrs, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", addr.IP, addr.Port))
	require.NoError(t, err)

	h, err := libp2p.New(libp2p.Identity(pkey), libp2p.ListenAddrs(addrs))
	require.NoError(t, err)

	return h
}
