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
	"fmt"
	"net"

	ma "github.com/multiformats/go-multiaddr"

	"github.com/obolnetwork/charon/app/errors"
)

type Config struct {
	// UDPBootnodes defines the discv5 boot node URLs.
	UDPBootnodes []string
	// UDPBootManifest enables using manifest ENRS as discv5 boot nodes.
	UDPBootManifest bool
	// UDPAddr defines the discv5 udp listen address.
	UDPAddr string
	// ExternalIP is the IP advertised by libp2p.
	ExternalIP string
	// ExternalHost is the DNS hostname advertised by libp2p.
	ExternalHost string
	// TCPAddrs defines the lib-p2p tcp listen addresses.
	TCPAddrs []string
	// Allowlist defines csv CIDR blocks for lib-p2p allowed connections.
	Allowlist string
	// Allowlist defines csv CIDR blocks for lib-p2p denied connections.
	Denylist string
	// BootnodeRelay enables circuit relay via bootnodes if direct connections fail.
	// Only applicable to charon nodes not bootnodes.
	BootnodeRelay bool
}

// ParseTCPAddrs returns the configured tcp addresses as typed net tcp addresses.
func (c Config) ParseTCPAddrs() ([]*net.TCPAddr, error) {
	res := make([]*net.TCPAddr, 0, len(c.TCPAddrs))

	for _, addr := range c.TCPAddrs {
		tcpAddr, err := resolveListenAddr(addr)
		if err != nil {
			return nil, err
		}
		res = append(res, tcpAddr)
	}

	return res, nil
}

// Multiaddrs returns the configured addresses as libp2p multiaddrs.
func (c Config) Multiaddrs() ([]ma.Multiaddr, error) {
	tcpAddrs, err := c.ParseTCPAddrs()
	if err != nil {
		return nil, err
	}

	res := make([]ma.Multiaddr, 0, len(tcpAddrs))

	for _, addr := range tcpAddrs {
		maddr, err := multiAddrFromIPPort(addr.IP, addr.Port)
		if err != nil {
			return nil, err
		}

		res = append(res, maddr)
	}

	return res, nil
}

func resolveListenAddr(addr string) (*net.TCPAddr, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, errors.Wrap(err, "resolve P2P bind addr")
	}

	if tcpAddr.IP == nil {
		return nil, errors.New("p2p bind IP not specified")
	}

	return tcpAddr, nil
}

// multiAddrFromIPPort returns a multiaddr composed of the provided ip (v4 or v6) and tcp port.
func multiAddrFromIPPort(ip net.IP, port int) (ma.Multiaddr, error) {
	if ip.To4() == nil && ip.To16() == nil {
		return nil, errors.New("invalid ip address")
	}

	var typ string
	if ip.To4() != nil {
		typ = "ip4"
	} else if ip.To16() != nil {
		typ = "ip6"
	}

	maddr, err := ma.NewMultiaddr(fmt.Sprintf("/%s/%s/tcp/%d", typ, ip.String(), port))
	if err != nil {
		return nil, errors.Wrap(err, "invalid multiaddr")
	}

	return maddr, nil
}
