// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package featureset

import (
	"context"
	"math"
	"strings"
	"testing"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

const (
	enable  status = math.MaxInt
	disable status = 0
)

// Config configures the feature set package.
type Config struct {
	// MinStatus defines the minimum enabled status.
	MinStatus string
	// Enabled overrides min status and enables a list of features.
	Enabled []string
	// Disabled overrides min status and disables a list of features.
	Disabled []string
}

// DefaultConfig returns the default config enabling only stable features.
func DefaultConfig() Config {
	return Config{
		MinStatus: statusStable.String(),
	}
}

// Init initialises the global feature set state.
func Init(ctx context.Context, config Config) error {
	initMu.Lock()
	defer initMu.Unlock()

	var ok bool
	for s := statusAlpha; s < statusSentinel; s++ {
		if strings.EqualFold(config.MinStatus, s.String()) {
			minStatus = s
			ok = true

			break
		}
	}
	if !ok {
		return errors.New("unknown min status", z.Str("min_status", config.MinStatus))
	}

	for _, f := range config.Enabled {
		var ok bool
		for feature := range state {
			if strings.EqualFold(string(feature), f) {
				state[feature] = enable
				ok = true
			}
		}
		if !ok {
			log.Warn(ctx, "Ignoring unknown enabled feature", nil, z.Str("feature", f))
		}
	}

	for _, f := range config.Disabled {
		var ok bool

		for feature := range state {
			if strings.EqualFold(string(feature), f) {
				state[feature] = disable
				ok = true
			}
		}
		if !ok {
			log.Warn(ctx, "Ignoring unknown disabled feature", nil, z.Str("feature", f))
		}
	}

	return nil
}

// EnableForT enables a feature for testing.
func EnableForT(t *testing.T, feature Feature) {
	t.Helper()

	initMu.Lock()
	defer initMu.Unlock()

	cache := state[feature]
	t.Cleanup(func() {
		state[feature] = cache
	})

	state[feature] = enable
}

// DisableForT disables a feature for testing.
func DisableForT(t *testing.T, feature Feature) {
	t.Helper()

	initMu.Lock()
	defer initMu.Unlock()

	cache := state[feature]
	t.Cleanup(func() {
		state[feature] = cache
	})

	state[feature] = disable
}
