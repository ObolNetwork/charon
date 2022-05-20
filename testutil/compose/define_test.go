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

package compose_test

import (
	"context"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/compose"
)

//go:generate go test . -update -clean

func TestDefine(t *testing.T) {
	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	err = compose.Define(context.Background(), dir, false, 1)
	require.NoError(t, err)

	conf, err := os.ReadFile(path.Join(dir, "compose.yml"))
	require.NoError(t, err)

	testutil.RequireGoldenBytes(t, conf)
}
