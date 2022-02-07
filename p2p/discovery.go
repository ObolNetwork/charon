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
	"net"

	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

// NewDiscNode starts and returns a discv5 UDP implementation.
func NewDiscNode(config Config, ln *enode.LocalNode, key *ecdsa.PrivateKey) (*discover.UDPv5, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", config.UDPAddr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	netlist, err := netutil.ParseNetlist(config.Allowlist)
	if err != nil {
		return nil, err
	}

	return discover.ListenV5(conn, ln, discover.Config{
		PrivateKey:  key,
		NetRestrict: netlist,
		Bootnodes:   nil, // TODO
	})
}

// NewLocalEnode returns a local enode and a peer DB or an error.
func NewLocalEnode(config Config, key *ecdsa.PrivateKey) (*enode.LocalNode, *enode.DB, error) {
	db, err := enode.OpenDB(config.DBPath)
	if err != nil {
		return nil, nil, err
	}

	addrs, err := config.ParseTCPAddrs()
	if err != nil {
		return nil, nil, err
	}

	node := enode.NewLocalNode(db, key)

	for _, addr := range addrs {
		if v4 := addr.IP.To4(); v4 != nil {
			node.Set(enr.IPv4(v4))
		} else if v6 := addr.IP.To16(); v6 != nil {
			node.Set(enr.IPv6(v6))
		}

		node.Set(enr.TCP(addr.Port))
	}

	return node, db, nil
}
