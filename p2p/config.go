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

	"github.com/multiformats/go-multiaddr"

	"github.com/obolnetwork/charon/app/errors"
)

type Config struct {
	DBPath    string
	UDPAddr   string   // discv5 listen address
	TCPAddrs  []string // lib-p2p listen addresses
	Allowlist string
	Denylist  string
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
func (c Config) Multiaddrs() ([]multiaddr.Multiaddr, error) {
	tcpAddrs, err := c.ParseTCPAddrs()
	if err != nil {
		return nil, err
	}

	res := make([]multiaddr.Multiaddr, 0, len(tcpAddrs))

	for _, addr := range tcpAddrs {

		var typ string
		if addr.IP.To4() != nil {
			typ = "ip4"
		} else if addr.IP.To16() != nil {
			typ = "ip6"
		} else {
			return nil, errors.New("invalid p2p address")
		}

		maddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/%s/%s/tcp/%d", typ, addr.IP.String(), addr.Port))
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
