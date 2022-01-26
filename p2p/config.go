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
	"errors"
	"fmt"
	"net"

	"github.com/multiformats/go-multiaddr"
	"github.com/spf13/viper"

	"github.com/obolnetwork/charon/internal/config"
)

type Config struct {
	Addrs   []string
	Netlist string
}

// TCPAddrs returns the configured addresses as tcp addresses.
func (c Config) TCPAddrs() ([]*net.TCPAddr, error) {
	var res []*net.TCPAddr
	for _, addr := range c.Addrs {
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
	var res []multiaddr.Multiaddr

	tcpAddrs, err := c.TCPAddrs()
	if err != nil {
		return nil, err
	}

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

// DefaultConfig constructs P2P config using viper.
func DefaultConfig() Config {
	return Config{
		Addrs:   viper.GetStringSlice(config.KeyP2P), // TODO support multiple IPs
		Netlist: viper.GetString(config.KeyNetlist),
	}
}

func resolveListenAddr(addr string) (*net.TCPAddr, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve P2P bind addr: %w", err)
	}

	if tcpAddr.IP == nil || tcpAddr.IP.IsUnspecified() {
		return nil, fmt.Errorf("IP not specified in P2P bind addr: \"%s\"", addr)
	}

	return tcpAddr, nil
}
