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
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/obolnetwork/charon/p2p"
)

// Peers keeps track about the node's own ENR and all other peers' ENRs.
type Peers struct {
	DB    *enode.DB
	Local *enode.LocalNode
}

// NewPeerDB opens the peer discovery database.
func NewPeerDB(config *Config, p2pConfig *p2p.Config, key *ecdsa.PrivateKey) (*Peers, error) {
	db, err := enode.OpenDB(config.DBPath)
	if err != nil {
		return nil, err
	}
	p := &Peers{DB: db}
	p.Local = enode.NewLocalNode(db, key)
	if v4 := p2pConfig.IPv4(); v4 != nil {
		p.Local.Set(enr.IPv4(v4))
	}
	if v6 := p2pConfig.IPv6(); v6 != nil {
		p.Local.Set(enr.IPv4(v6))
	}
	p.Local.Set(enr.TCP(p2pConfig.Port))
	return p, nil
}

// Close saves and closes the peer discovery database.
//
// The Peers object must not be used after closing.
func (c *Peers) Close() {
	c.Local = nil
	c.DB.Close()
	c.DB = nil
}
