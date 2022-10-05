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

package p2p_test

import (
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestSendReceive(t *testing.T) {
	var (
		protocolID  = protocol.ID("test")
		errNegative = errors.New("negative slot")
		ctx         = context.Background()
		server      = testutil.CreateHost(t, testutil.AvailableAddr(t))
		client      = testutil.CreateHost(t, testutil.AvailableAddr(t))
	)

	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

	// Register the server handler that either:
	//  - Errors is slot is negative
	//  - Echos the duty request if slot is even
	//  - Returns nothing is slot is odd
	p2p.RegisterHandler("server", server, protocolID,
		func() proto.Message { return new(pbv1.Duty) },
		func(ctx context.Context, peerID peer.ID, req proto.Message) (proto.Message, bool, error) {
			require.Equal(t, client.ID(), peerID)
			duty, ok := req.(*pbv1.Duty)
			require.True(t, ok)

			if duty.Slot < 0 {
				return nil, false, errNegative
			} else if duty.Slot%2 == 0 {
				return duty, true, nil
			} else {
				return nil, false, nil
			}
		},
	)

	sendReceive := func(slot int64) (*pbv1.Duty, error) {
		resp := new(pbv1.Duty)
		err := p2p.SendReceive(ctx, client, server.ID(), &pbv1.Duty{Slot: slot}, resp, protocolID)

		return resp, err
	}

	t.Run("server error", func(t *testing.T) {
		_, err := sendReceive(-1)
		require.ErrorContains(t, err, "no response")
	})

	t.Run("ok", func(t *testing.T) {
		slot := int64(100)
		resp, err := sendReceive(slot)
		require.NoError(t, err)
		require.Equal(t, slot, resp.Slot)
	})

	t.Run("empty response", func(t *testing.T) {
		_, err := sendReceive(101)
		require.ErrorContains(t, err, "no response")
	})
}
