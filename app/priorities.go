// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
func (c *mutableConfig) BuilderAPI(_ uint64) bool {
	// NOTE: Dynamic BuilderAPI config disabled since VCs do not support it.
	return c.conf.BuilderAPI
}
