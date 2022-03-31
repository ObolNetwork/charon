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

	"github.com/obolnetwork/charon/app/errors"
)

// NewUDPNode starts and returns a discv5 UDP implementation.
func NewUDPNode(config Config, ln *enode.LocalNode, key *ecdsa.PrivateKey,
	enrs []enr.Record,
) (*discover.UDPv5, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", config.UDPAddr)
	if err != nil {
		return nil, errors.Wrap(err, "resolve udp address")
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, errors.Wrap(err, "parse udp address")
	}

	netlist, err := netutil.ParseNetlist(config.Allowlist)
	if err != nil {
		return nil, errors.Wrap(err, "parse allow list")
	}

	var bootnodes []*enode.Node

	for _, seed := range config.UDPBootnodes {
		node, err := enode.Parse(enode.V4ID{}, seed)
		if err != nil {
			return nil, errors.Wrap(err, "invalid bootnode url")
		}

		bootnodes = append(bootnodes, node)
	}

	if config.UDPBootManifest {
		for _, record := range enrs {
			record := record
			node, err := enode.New(enode.V4ID{}, &record)
			if err != nil {
				return nil, errors.Wrap(err, "new enode")
			}

			if ln.ID() == node.ID() {
				// Do not add local node as bootnode
				continue
			}

			bootnodes = append(bootnodes, node)
		}
	}

	node, err := discover.ListenV5(conn, ln, discover.Config{
		PrivateKey:  key,
		NetRestrict: netlist,
		Bootnodes:   bootnodes,
	})
	if err != nil {
		return nil, errors.Wrap(err, "discv5 listen")
	}

	return node, nil
}

// NewLocalEnode returns a local enode and a peer DB or an error.
func NewLocalEnode(config Config, key *ecdsa.PrivateKey) (*enode.LocalNode, *enode.DB, error) {
	db, err := enode.OpenDB(config.DBPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "open peer db")
	}

	udpAddr, err := net.ResolveUDPAddr("udp", config.UDPAddr)
	if err != nil {
		return nil, nil, errors.Wrap(err, "resolve udp address")
	}

	tcpAddrs, err := config.ParseTCPAddrs()
	if err != nil {
		return nil, nil, err
	}

	node := enode.NewLocalNode(db, key)

	for _, addr := range tcpAddrs {
		if v4 := addr.IP.To4(); v4 != nil {
			node.Set(enr.IPv4(v4))
		} else if v6 := addr.IP.To16(); v6 != nil {
			node.Set(enr.IPv6(v6))
		}
		node.Set(enr.TCP(addr.Port))
	}

	node.SetFallbackIP(udpAddr.IP)
	node.SetFallbackUDP(udpAddr.Port)

	if config.ExternalIP != "" {
		ip := net.ParseIP(config.ExternalIP)
		if ip.To4() == nil && ip.To16() == nil {
			return nil, nil, errors.New("invalid p2p external ip")
		}

		node.SetFallbackIP(ip)
		node.SetStaticIP(ip)
	}

	if config.ExteranlHost != "" {
		ips, err := net.LookupIP(config.ExteranlHost)
		if err != nil || len(ips) == 0 {
			return nil, nil, errors.Wrap(err, "could not resolve p2p external host")
		}

		// Use first IPv4 returned from the resolver.
		// TODO(corver): Figure out how to get ipv6 to work
		for _, ip := range ips {
			if ip.To4() == nil {
				continue
			}
			node.SetFallbackIP(ip)
		}
	}

	return node, db, nil
}
