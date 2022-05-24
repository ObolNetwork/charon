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

package compose

import (
	"context"
	"fmt"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// New creates a new compose config file from flags.
func New(ctx context.Context, dir string, conf Config) error {
	conf.Step = stepNew

	log.Info(ctx, "Writing config to compose dir",
		z.Str("dir", dir),
		z.Str("config", fmt.Sprintf("%#v", conf)),
	)

	return writeConfig(dir, conf)
}
