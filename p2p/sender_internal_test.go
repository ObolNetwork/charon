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

package p2p

import (
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
)

func TestSenderAddResult(t *testing.T) {
	sender := new(Sender)
	peerID := peer.ID("test")
	failure := errors.New("failure")
	success := error(nil)

	assertFailing := func(t *testing.T, expect bool) {
		t.Helper()
		var state peerState
		if val, ok := sender.states.Load(peerID); ok {
			state = val.(peerState)
		}
		require.Equal(t, expect, state.failing)
	}

	add := func(result error) {
		sender.addResult(context.Background(), peerID, result)
	}

	assertFailing(t, false) // Start not failing
	add(failure)
	assertFailing(t, true) // Single failure changes state to failing.
	add(failure)
	assertFailing(t, true) // Still failing.
	add(success)
	assertFailing(t, true) // Still failing.
	add(success)
	assertFailing(t, true) // Still failing.
	add(success)
	assertFailing(t, false) // Hysteresis success changes state to success.
	add(success)
	assertFailing(t, false) // Still success
	add(success)
	assertFailing(t, false) // Still success
	add(failure)
	assertFailing(t, true) // Single failure changes state to failing.

	// TODO(corver): Assert logs
	// INFO P2P sending failing {"peer": "better-week"}
	// INFO P2P sending recovered {"peer": "better-week"}
	// INFO P2P sending failing {"peer": "better-week"}
}
