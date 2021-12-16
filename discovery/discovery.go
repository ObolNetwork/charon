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

// Package discovery provides peer discovery.
package discovery

import (
	"crypto/ecdsa"
	"net"

	"github.com/ethereum/go-ethereum/p2p/discover"
	zerologger "github.com/rs/zerolog/log"
)

var log = zerologger.With().Str("component", "discovery").Logger()

// Node participates in the discv5 network.
type Node struct {
	Config     *Config
	Peers      *Peers
	PrivateKey *ecdsa.PrivateKey

	conn   *net.UDPConn
	discv5 *discover.UDPv5
}

func NewNode(config *Config, peers *Peers, key *ecdsa.PrivateKey) *Node {
	return &Node{
		Config:     config,
		Peers:      peers,
		PrivateKey: key,
	}
}

// Listen starts up the discv5 UDP listener and node logic.
func (n *Node) Listen() (err error) {
	n.conn, err = net.ListenUDP("udp", &n.Config.ListenAddr)
	if err != nil {
		return err
	}
	n.discv5, err = discover.ListenV5(n.conn, n.Peers.Local, discover.Config{
		PrivateKey:  n.PrivateKey,
		NetRestrict: n.Config.P2P.Netlist,
		Bootnodes:   nil, // TODO
	})
	log.Info().Msgf("Starting discv5 on %s", n.Config.ListenAddr.String())
	return
}

func (n *Node) Close() {
	n.discv5.Close()
}
