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

package app

import (
	"sync"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/infosync"
)

// newMutableConfig returns a new mutable config.
func newMutableConfig(conf Config) *mutableConfig {
	return &mutableConfig{conf: conf}
}

// mutableConfig defines mutable cluster wide config.
type mutableConfig struct {
	conf Config

	mu       sync.RWMutex
	infosync *infosync.Component
}

func (p *mutableConfig) SetInfoSync(infosync *infosync.Component) {
	p.mu.Lock()
	p.infosync = infosync
	p.mu.Unlock()
}

func (p *mutableConfig) getInfoSync() (*infosync.Component, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.infosync, p.infosync != nil
}

// BuilderAPI returns true if the cluster supports the builder API for the provided slot.
func (p *mutableConfig) BuilderAPI(slot int64) bool {
	isync, ok := p.getInfoSync()
	if !ok {
		return p.conf.BuilderAPI
	}

	for _, proposal := range isync.Proposals(slot) {
		if proposal == core.ProposalTypeBuilder {
			return true
		}
	}

	return false
}
