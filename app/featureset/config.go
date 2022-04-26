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
	var ok bool
	for s := statusAlpha; s < statusSentinel; s++ {
		if strings.ToLower(config.MinStatus) == strings.ToLower(s.String()) {
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
			if strings.ToLower(string(feature)) == strings.ToLower(f) {
				state[feature] = enable
				ok = true
			}
		}
		if !ok {
			log.Warn(ctx, "Ignoring unknown enabled feature", z.Str("feature", f))
		}
	}

	for _, f := range config.Disabled {
		var ok bool
		for feature := range state {
			if strings.ToLower(string(feature)) == strings.ToLower(f) {
				state[feature] = disable
				ok = true
			}
		}
		if !ok {
			log.Warn(ctx, "Ignoring unknown disabled feature", z.Str("feature", f))
		}
	}

	return nil
}

// EnableForT enables a feature for testing.
func EnableForT(t *testing.T, feature Feature) {
	t.Helper()

	cache := state[feature]
	t.Cleanup(func() {
		state[feature] = cache
	})

	state[feature] = enable
}

// DisableForT disables a feature for testing.
func DisableForT(t *testing.T, feature Feature) {
	t.Helper()

	cache := state[feature]
	t.Cleanup(func() {
		state[feature] = cache
	})

	state[feature] = disable
}
