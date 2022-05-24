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
	"bytes"
	"context"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
)

func TestDefineDKG(t *testing.T) {
	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	conf := NewDefaultConfig()
	conf.KeyGen = "dkg"
	conf.Step = stepNew
	p2pSeed = 1
	noPull = true
	require.NoError(t, writeConfig(dir, conf))

	err = Define(context.Background(), dir)
	require.NoError(t, err)

	dc, err := os.ReadFile(path.Join(dir, "docker-compose.yml"))
	require.NoError(t, err)
	dc = bytes.ReplaceAll(dc, []byte(dir), []byte("testdir"))

	testutil.RequireGoldenBytes(t, dc)
}

func TestDefineCreate(t *testing.T) {
	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	conf := NewDefaultConfig()
	conf.KeyGen = "create"
	conf.Step = stepNew
	noPull = true
	require.NoError(t, writeConfig(dir, conf))

	err = Define(context.Background(), dir)
	require.NoError(t, err)

	dc, err := os.ReadFile(path.Join(dir, "docker-compose.yml"))
	require.NoError(t, err)
	dc = bytes.ReplaceAll(dc, []byte(dir), []byte("testdir"))

	testutil.RequireGoldenBytes(t, dc)
}
