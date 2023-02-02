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

	"github.com/obolnetwork/charon/core/infosync"
)

// newMutableConfig returns a new mutable config.
func newMutableConfig(ctx context.Context, conf Config) *mutableConfig {
	return &mutableConfig{
		ctx:  ctx,
		conf: conf,
	}
}

// mutableConfig defines mutable cluster wide config.
type mutableConfig struct {
	ctx  context.Context
	conf Config

	mu       sync.Mutex
	infosync *infosync.Component
}

func (c *mutableConfig) SetInfoSync(infosync *infosync.Component) {
	c.mu.Lock()
	c.infosync = infosync
	c.mu.Unlock()
}

//nolint:unused // TODO: Remove this once we have a use case.
func (c *mutableConfig) getInfoSync() (*infosync.Component, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.infosync, c.infosync != nil
}

// BuilderAPI returns true if the cluster supports the builder API for the provided slot.
func (c *mutableConfig) BuilderAPI(_ int64) bool {
	// TODO(corver): Dynamic BuilderAPI config disabled since VCs do not support it.
	return c.conf.BuilderAPI
}
