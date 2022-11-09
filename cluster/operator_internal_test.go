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

package cluster

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/p2p"
)

func TestGetName(t *testing.T) {
	enr := "enr:-JG4QKXiqTRo5OmRPutHAjW93YAL0eo63NKDHTb2viARXiYaCJZXZeiT3-STunsuvTRxwP8G8CmhSvQLYqdqfZ8kL3aGAYDhssjugmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQOFWExWolIvyowQNrlUAIGqnBaHJexfLJE6zyFcovULYoN0Y3CCPoODdWRwgj6E"
	op := Operator{ENR: enr}

	p1, err := op.Peer()
	require.NoError(t, err)
	first := p2p.PeerName(p1.ID)
	require.True(t, strings.Contains(first, "-"))
	require.Equal(t, first, "wrong-council")

	p2, err := op.Peer()
	require.NoError(t, err)
	second := p2p.PeerName(p2.ID)
	require.True(t, strings.Contains(second, "-"))

	// The two names must be the same.
	require.Equal(t, first, second)
}
