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

package cmd

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

func TestRunNewEnr(t *testing.T) {
	temp, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	got := runNewENR(io.Discard, p2p.Config{}, temp, false)
	expected := errors.New("private key not found. If this is your first time running this client, create one with `charon create enr`.", z.Str("enr_path", p2p.KeyPath(temp)))
	require.Equal(t, expected.Error(), got.Error())
}
