// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"sync"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/eth2util/enr"
)

// Peer represents a peer in the libp2p network, either a charon node or a relay.
type Peer struct {
	// ID is a libp2p peer identity.
	ID peer.ID

	// Addrs is the list of libp2p multiaddresses of the peer.
	Addrs []ma.Multiaddr

	// Index is the order of this node in the cluster.
	// This is only applicable to charon nodes, not relays.
	Index int

	// Name represents a human friendly name for the peer.
	Name string
}

// ShareIdx returns share index of this Peer. ShareIdx is 1-indexed while peerIdx is 0-indexed.
func (p Peer) ShareIdx() int {
	return p.Index + 1
}

// PublicKey returns peer public key.
func (p Peer) PublicKey() (*k1.PublicKey, error) {
	return PeerIDToKey(p.ID)
}

// AddrInfo returns the libp2p peer addr info (peer ID and multiaddrs).
func (p Peer) AddrInfo() peer.AddrInfo {
	return peer.AddrInfo{
		ID:    p.ID,
		Addrs: p.Addrs,
	}
}

// NewRelayPeer returns a new relay peer (-1 index).
func NewRelayPeer(info peer.AddrInfo) Peer {
	return Peer{
		ID:    info.ID,
		Addrs: info.Addrs,
		Name:  PeerName(info.ID),
	}
}

// NewPeerFromENR returns a new charon peer without addresses.
func NewPeerFromENR(record enr.Record, index int) (Peer, error) {
	id, err := PeerIDFromKey(record.PubKey)
	if err != nil {
		return Peer{}, err
	}

	return Peer{
		ID:    id,
		Index: index,
		Name:  PeerName(id),
	}, nil
}

// PeerIDToKey returns the public key of the peer ID.
func PeerIDToKey(p peer.ID) (*k1.PublicKey, error) {
	pk, err := p.ExtractPublicKey()
	if err != nil {
		return nil, errors.Wrap(err, "extract pubkey")
	}

	return k1util.PublicKeyFromLibP2P(pk)
}

// PeerIDFromKey returns the peer ID of the public key.
func PeerIDFromKey(pubkey *k1.PublicKey) (peer.ID, error) {
	id, err := peer.IDFromPublicKey((*crypto.Secp256k1PublicKey)(pubkey))
	if err != nil {
		return "", errors.Wrap(err, "p2p id from pubkey")
	}

	return id, nil
}

// NewMutablePeer returns a new non-empty mutable peer.
func NewMutablePeer(p Peer) *MutablePeer {
	return &MutablePeer{peer: &p}
}

// MutablePeer defines a mutable peer used mostly for stateless relays that change ID on restart
// but have a consistent URL to resolve them. The zero value is a valid empty MutablePeer.
type MutablePeer struct {
	mu   sync.Mutex
	peer *Peer
	subs []func(Peer)
}

// Set updates the mutable peer and calls all subscribers.
func (p *MutablePeer) Set(peer Peer) {
	p.mu.Lock()
	p.peer = &peer
	clone := append([]func(Peer){}, p.subs...)
	p.mu.Unlock()

	for _, sub := range clone {
		sub(peer)
	}
}

// Peer returns the current peer or false if not available.
func (p *MutablePeer) Peer() (Peer, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.peer == nil {
		return Peer{}, false
	}

	return *p.peer, true
}

// Subscribe registers a function that is called when the peer is updated.
func (p *MutablePeer) Subscribe(sub func(Peer)) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.subs = append(p.subs, sub)
}

// VerifyP2PKey returns an error if the p2pkey doesn't match any lock operator ENR.
func VerifyP2PKey(peers []Peer, key *k1.PrivateKey) error {
	want := key.PubKey()

	for _, p := range peers {
		pk, err := p.ID.ExtractPublicKey()
		if err != nil {
			return errors.Wrap(err, "extract pubkey from peer id")
		}

		got, err := k1util.PublicKeyFromLibP2P(pk)
		if err != nil {
			return err
		}

		if got.IsEqual(want) {
			return nil
		}
	}

	return errors.New("unknown private key provided, it doesn't match any public key encoded inside the operator ENRs") // This message seems to know something about the context in which it is used :(
}
