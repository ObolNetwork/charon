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
	"text/template"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -update -clean

func TestLockCompose(t *testing.T) {
	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	conf := NewDefaultConfig()
	err = Lock(context.Background(), dir, conf)
	require.NoError(t, err)

	compose, err := os.ReadFile(path.Join(dir, "docker-compose.yml"))
	require.NoError(t, err)
	compose = bytes.ReplaceAll(compose, []byte(dir), []byte("testdir"))

	testutil.RequireGoldenBytes(t, compose)
}

func TestParseTemplate(t *testing.T) {
	_, err := template.New("").Parse(string(tmpl))
	require.NoError(t, err)
}
