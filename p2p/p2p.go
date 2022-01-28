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

package p2p

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	noise "github.com/libp2p/go-libp2p-noise"
	zerologger "github.com/rs/zerolog/log"

	"github.com/obolnetwork/charon/runner/version"
)

var log = zerologger.With().Str("component", "p2p").Logger()

type Node struct {
	host.Host
}

// NewNode starts the libp2p subsystem.
func NewNode(cfg Config, key *ecdsa.PrivateKey, connGater *ConnGater) (*Node, error) {
	if key == nil {
		return nil, fmt.Errorf("missing private key")
	}

	addrs, err := cfg.Multiaddrs()
	if err != nil {
		return nil, fmt.Errorf("invalid multiaddrs: %w", err)
	}

	// Init options.
	opts := []libp2p.Option{
		// Set P2P identity key.
		libp2p.Identity(crypto.PrivKey((*crypto.Secp256k1PrivateKey)(key))),
		// Set noise-libp2p handshake.
		libp2p.Security(noise.ID, noise.New),
		// Set listen addresses.
		libp2p.ListenAddrs(addrs...),
		// Set up user-agent.
		libp2p.UserAgent("ObolNetwork-Charon/" + version.Version),
		// Limit connections to DV peers.
		libp2p.ConnectionGater(connGater),
	}

	// Create node.
	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, err
	}

	log.Info().Msgf("Starting P2P interface on %v", h.Addrs())

	return &Node{h}, nil
}
