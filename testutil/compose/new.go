// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package compose

import (
	"context"
	"fmt"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// New creates a new compose config file from flags.
func New(ctx context.Context, dir string, conf Config) error {
	if err := Clean(ctx, dir); err != nil {
		return err
	}

	conf.Step = stepNew

	log.Info(ctx, "Writing config to compose dir",
		z.Str("dir", dir),
		z.Str("config", fmt.Sprintf("%#v", conf)),
	)

	return WriteConfig(dir, conf)
}
