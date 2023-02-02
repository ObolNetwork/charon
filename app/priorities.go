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
	"context"
	"sync"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/infosync"
)

// newMutableConfig returns a new mutable config.
func newMutableConfig(ctx context.Context, conf Config) *mutableConfig {
	return &mutableConfig{
		ctx:            ctx,
		conf:           conf,
		prevBuilderAPI: conf.BuilderAPI,
	}
}

// mutableConfig defines mutable cluster wide config.
type mutableConfig struct {
	ctx  context.Context
	conf Config

	mu             sync.Mutex
	infosync       *infosync.Component
	prevBuilderAPI bool
}

func (c *mutableConfig) SetInfoSync(infosync *infosync.Component) {
	c.mu.Lock()
	c.infosync = infosync
	c.mu.Unlock()
}

func (c *mutableConfig) getInfoSync() (*infosync.Component, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.infosync, c.infosync != nil
}

// casBuilderAPI compares-and-swaps the new builderAPI value, returning true if it was different.
func (c *mutableConfig) casBuilderAPI(builderAPI bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	diff := c.prevBuilderAPI != builderAPI
	c.prevBuilderAPI = builderAPI

	return diff
}

// BuilderAPI returns true if the cluster supports the builder API for the provided slot.
func (c *mutableConfig) BuilderAPI(slot int64) bool {
	isync, ok := c.getInfoSync()
	if !ok { // Infosync not available yet.
		return c.conf.BuilderAPI
	}

	var builderAPI bool
	for _, proposal := range isync.Proposals(slot) {
		if proposal == core.ProposalTypeBuilder {
			builderAPI = true
			break
		}
	}

	if c.casBuilderAPI(builderAPI) {
		// TODO(corver): This might flip flop due to provided slot.
		log.Info(c.ctx, "Dynamic cluster-wide BuilderAPI config changed", z.Bool("enabled", builderAPI), z.I64("slot", slot))
	}

	return false
}
