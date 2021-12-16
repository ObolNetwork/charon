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

package discovery

import (
	"fmt"
	"net"

	"github.com/obolnetwork/charon/internal/config"
	"github.com/obolnetwork/charon/p2p"
	zerologger "github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type Config struct {
	P2P        *p2p.Config
	DBPath     string
	ListenAddr net.UDPAddr
}

// DefaultConfig constructs discovery config using viper.
func DefaultConfig(p2pConfig *p2p.Config) *Config {
	listenAddr := viper.GetString(config.KeyDiscV5)
	addr, port, err := resolveListenAddr(listenAddr)
	if err != nil {
		zerologger.Fatal().Err(err).Msg("Invalid discovery listen address")
	}
	c := &Config{
		P2P:        p2pConfig,
		DBPath:     viper.GetString(config.KeyNodeDB),
		ListenAddr: net.UDPAddr{IP: addr, Port: port},
	}
	return c
}

func resolveListenAddr(listenStr string) (addr net.IP, port int, err error) {
	udpAddr, err := net.ResolveUDPAddr("udp", listenStr)
	if err != nil {
		return nil, -1, fmt.Errorf("failed to resolve discovery bind addr: %w", err)
	}
	return udpAddr.IP, udpAddr.Port, nil
}
