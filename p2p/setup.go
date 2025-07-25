// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"context"
	"encoding/hex"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

// SetupP2P returns a started libp2p tcp node and a shutdown function.
func SetupP2P(ctx context.Context, key *k1.PrivateKey, config Config, peers []Peer, defHash []byte) (host.Host, func(), error) {
	var peerIDs []peer.ID
	for _, p := range peers {
		peerIDs = append(peerIDs, p.ID)
	}

	if err := VerifyP2PKey(peers, key); err != nil {
		return nil, nil, err
	}

	relays, err := NewRelays(ctx, config.Relays, hex.EncodeToString(defHash))
	if err != nil {
		return nil, nil, err
	}

	connGater, err := NewConnGater(peerIDs, relays)
	if err != nil {
		return nil, nil, err
	}

	tcpNode, err := NewTCPNode(ctx, config, key, connGater, false)
	if err != nil {
		return nil, nil, err
	}

	RegisterConnectionLogger(ctx, tcpNode, peerIDs)

	for _, relay := range relays {
		go NewRelayReserver(tcpNode, relay)(ctx)
	}

	go NewRelayRouter(tcpNode, peerIDs, relays)(ctx)

	return tcpNode, func() {
		_ = tcpNode.Close()
	}, nil
}
