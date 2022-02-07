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
	"context"
	"crypto/ecdsa"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	noise "github.com/libp2p/go-libp2p-noise"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
)

// NewNode returns a started libp2p node.
func NewNode(cfg Config, key *ecdsa.PrivateKey, connGater ConnGater) (host.Host, error) {
	if key == nil {
		return nil, errors.New("missing private key")
	}

	addrs, err := cfg.Multiaddrs()
	if err != nil {
		return nil, err
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

		// TODO(corver): Add a connection manager.
	}

	return libp2p.New(opts...)
}

// ConnectPeers attempts to connect to cluster peers by their addresses defined in manifest ENRs.
func ConnectPeers(ctx context.Context, h host.Host, enrs []enr.Record, attempts int) error {
	if attempts == 0 {
		return nil
	}

	for _, e := range enrs {
		info, err := cluster.PeerInfoFromENR(e)
		if err != nil {
			return err
		}

		if info.ID == h.ID() {
			// Do not connect to self.
			continue
		}

		connect := func() bool {
			err := h.Connect(ctx, info)
			if err != nil {
				log.Warn(ctx, "Failed connecting to manifest peer", z.Str("peer", ShortID(info.ID)),
					z.Str("error", err.Error()))
			}
			return err == nil
		}

		for i := 0; i < attempts; i++ {
			if connect() {
				continue
			}
			time.Sleep(time.Second) // Improve backoff
		}
	}

	return nil
}
