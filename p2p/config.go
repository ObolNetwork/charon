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
	"strconv"

	"github.com/ethereum/go-ethereum/p2p/netutil"
	"github.com/multiformats/go-multiaddr"
	"github.com/obolnetwork/charon/internal/config"
	zerologger "github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type Config struct {
	IPAddrs []net.IP
	Port    int
	Netlist *netutil.Netlist
}

// DefaultConfig constructs P2P config using viper.
func DefaultConfig() *Config {
	listenAddr := viper.GetString(config.KeyP2P)
	addr, port, err := resolveListenAddr(listenAddr)
	if err != nil {
		zerologger.Fatal().Err(err).Msg("Invalid P2P listen address")
	}
	netlistStr := viper.GetString(config.KeyNetlist)
	var netlist *netutil.Netlist
	if netlistStr != "" {
		var err error
		netlist, err = netutil.ParseNetlist(netlistStr)
		if err != nil {
			zerologger.Fatal().Err(err).Msg("Invalid netlist")
		}
	}
	c := &Config{
		IPAddrs: []net.IP{addr}, // TODO support multiple IPs
		Port:    port,
		Netlist: netlist,
	}
	return c
}

func resolveListenAddr(listenStr string) (addr net.IP, port int, err error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", listenStr)
	if err != nil {
		return nil, -1, fmt.Errorf("failed to resolve P2P bind addr: %w", err)
	}
	if tcpAddr.IP == nil || tcpAddr.IP.IsUnspecified() {
		return nil, -1, fmt.Errorf("IP not specified in P2P bind addr: \"%s\"", listenStr)
	}
	return tcpAddr.IP, tcpAddr.Port, nil
}

// IPv4 returns the first configured IPv4 address or nil.
func (c *Config) IPv4() net.IP {
	for _, a := range c.IPAddrs {
		if len(a) == net.IPv4len {
			return a
		}
	}
	return nil
}

// IPv6 returns the first configured IPv6 address or nil.
func (c *Config) IPv6() net.IP {
	for _, a := range c.IPAddrs {
		if len(a) == net.IPv6len {
			return a
		}
	}
	return nil
}

// Multiaddrs returns the configured IP addresses as libp2p multiaddrs.
func (c *Config) Multiaddrs() (addrs []multiaddr.Multiaddr, err error) {
	for _, ipAddr := range c.IPAddrs {
		var maddrStr string
		v4 := ipAddr.To4()
		if v4 != nil {
			maddrStr = "/ip4/" + ipAddr.String() + "/tcp/" + strconv.Itoa(c.Port)
		} else if len(ipAddr) == net.IPv6len {
			maddrStr = "/ip6/" + ipAddr.String() + "/tcp/" + strconv.Itoa(c.Port)
		} else {
			panic(fmt.Sprintf("invalid IP addr: %x", []byte(ipAddr)))
		}
		maddr, err := multiaddr.NewMultiaddr(maddrStr)
		if err != nil {
			return addrs, err
		}
		addrs = append(addrs, maddr)
	}
	return
}
