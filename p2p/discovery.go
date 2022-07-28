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

package p2p

import (
	"crypto/ecdsa"
	"net"

	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/netutil"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

// UDPNode wraps a discv5 udp node and adds the bootnodes relays.
type UDPNode struct {
	*discover.UDPv5
	Relays []Peer
}

// NewUDPNode starts and returns a discv5 UDP implementation.
func NewUDPNode(config Config, ln *enode.LocalNode,
	key *ecdsa.PrivateKey, bootnodes []*enode.Node,
) (*discover.UDPv5, error) {
	// Setup discv5 udp listener.
	udpAddr, err := net.ResolveUDPAddr("udp", config.UDPAddr)
	if err != nil {
		return nil, errors.Wrap(err, "resolve udp address")
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, errors.Wrap(err, "parse udp address")
	}

	var allowList *netutil.Netlist
	if config.Allowlist != "" {
		allowList, err = netutil.ParseNetlist(config.Allowlist) // Note empty string results in "none allowed".
		if err != nil {
			return nil, errors.Wrap(err, "parse allow list")
		}
	}

	node, err := discover.ListenV5(conn, ln, discover.Config{
		PrivateKey:  key,
		NetRestrict: allowList,
		Bootnodes:   bootnodes,
	})
	if err != nil {
		return nil, errors.Wrap(err, "discv5 listen")
	}

	return node, nil
}

// NewLocalEnode returns a local enode and a peer DB or an error.
func NewLocalEnode(config Config, key *ecdsa.PrivateKey) (*enode.LocalNode, *enode.DB, error) {
	// Empty DB Path creates a new in-memory node database without a persistent backend
	db, err := enode.OpenDB("")
	if err != nil {
		return nil, nil, errors.Wrap(err, "open peer db")
	}

	node := enode.NewLocalNode(db, key)

	// Configure enode with ip and port for tcp libp2p
	tcpAddrs, err := config.ParseTCPAddrs()
	if err != nil {
		return nil, nil, err
	}

	for _, addr := range tcpAddrs {
		if v4 := addr.IP.To4(); v4 != nil {
			node.Set(enr.IPv4(v4))
		} else if v6 := addr.IP.To16(); v6 != nil {
			node.Set(enr.IPv6(v6))
		}
		node.Set(enr.TCP(addr.Port))
	}

	// Configure enode with ip and port for udp discv5
	udpAddr, err := net.ResolveUDPAddr("udp", config.UDPAddr)
	if err != nil {
		return nil, nil, errors.Wrap(err, "resolve udp address")
	}
	node.SetFallbackIP(udpAddr.IP)
	node.SetFallbackUDP(udpAddr.Port)

	// Configure enode with external (advertised) IP
	if config.ExternalIP != "" {
		ip := net.ParseIP(config.ExternalIP)
		if ip.To4() == nil && ip.To16() == nil {
			return nil, nil, errors.New("invalid p2p external ip")
		}

		node.SetFallbackIP(ip)
		node.SetStaticIP(ip)
	}

	// Configure enode with external (advertised) hostname
	if config.ExternalHost != "" {
		ips, err := net.LookupIP(config.ExternalHost)
		if err != nil || len(ips) == 0 {
			return nil, nil, errors.Wrap(err, "resolve IP of p2p external host flag",
				z.Str("p2p_external_hostname", config.ExternalHost))
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
