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
	"fmt"
	"net"

	ma "github.com/multiformats/go-multiaddr"

	"github.com/obolnetwork/charon/app/errors"
)

type Config struct {
	// DBPath defines the discv5 peer database file path.
	DBPath string
	// UDPBootnodes defines the discv5 boot node URLs (in addition to manifest ENRs).
	UDPBootnodes []string
	// UDPAddr defines the discv5 udp listen address.
	UDPAddr string
	// TCPAddrs defines the lib-p2p tcp listen addresses.
	TCPAddrs []string
	// Allowlist defines csv CIDR blocks for lib-p2p allowed connections.
	Allowlist string
	// Allowlist defines csv CIDR blocks for lib-p2p denied connections.
	Denylist string
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
	var typ string
	if ip.To4() != nil {
		typ = "ip4"
	} else if ip.To16() != nil {
		typ = "ip6"
	} else {
		return nil, errors.New("invalid ip address")
	}

	maddr, err := ma.NewMultiaddr(fmt.Sprintf("/%s/%s/tcp/%d", typ, ip.String(), port))
	if err != nil {
		return nil, errors.Wrap(err, "invalid multiaddr")
	}

	return maddr, nil
}
