// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"context"
	"crypto/rand"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	pbv2 "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/pb"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/proto"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/util"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

// maxHopMsgSize is the maximum size of a circuit v2 hop message.
const maxHopMsgSize = 4096

// defaultProbeTimeout bounds the probe when the context has no deadline.
const defaultProbeTimeout = 10 * time.Second

// RelayHasReservation returns whether the relay currently holds a reservation for the target peer.
//
// It sends a circuit v2 hop CONNECT for the target from a throwaway host with a fresh random key
// (never the target's), so it works while the target is running. The relay answers NO_RESERVATION
// if the target has no reservation.
//
// A CONNECTION_FAILED answer also counts as a reservation: the relay only returns it after finding
// one for the target, so the relay is occupied by that peer ID and must not be used.
//
// The probe is bounded by the context deadline, or by a 10s default if it has none.
//
// Side effect: if a reservation exists, the relay opens a stop stream to the reserved peer before
// answering OK, so the running target sees one inbound relayed connection that fails when the
// probe resets the stream.
func RelayHasReservation(ctx context.Context, relay peer.AddrInfo, target peer.ID) (bool, error) {
	key, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		return false, errors.Wrap(err, "generate probe key")
	}

	h, err := libp2p.New(libp2p.Identity(key), libp2p.NoListenAddrs)
	if err != nil {
		return false, errors.Wrap(err, "new probe host")
	}
	defer h.Close()

	if err := h.Connect(ctx, relay); err != nil {
		return false, errors.Wrap(err, "connect to relay")
	}

	s, err := h.NewStream(ctx, relay.ID, proto.ProtoIDv2Hop)
	if err != nil {
		return false, errors.Wrap(err, "open hop stream")
	}
	// Reset rather than close: the probe never completes the circuit and must abort the relay's handshake.
	defer func() { _ = s.Reset() }()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(defaultProbeTimeout)
	}

	if err := s.SetDeadline(deadline); err != nil {
		return false, errors.Wrap(err, "set stream deadline")
	}

	stop := context.AfterFunc(ctx, func() { _ = s.Reset() })
	defer stop()

	w := util.NewDelimitedWriter(s)
	req := &pbv2.HopMessage{
		Type: pbv2.HopMessage_CONNECT.Enum(),
		Peer: &pbv2.Peer{Id: []byte(target)},
	}

	err = w.WriteMsg(req)
	if err != nil {
		return false, errors.Wrap(err, "write hop connect")
	}

	r := util.NewDelimitedReader(s, maxHopMsgSize)

	var resp pbv2.HopMessage
	if err := r.ReadMsg(&resp); err != nil {
		return false, errors.Wrap(err, "read hop response")
	}

	switch resp.GetStatus() {
	case pbv2.Status_OK, pbv2.Status_CONNECTION_FAILED:
		return true, nil
	case pbv2.Status_NO_RESERVATION:
		return false, nil
	default:
		return false, errors.New("unexpected relay status", z.Str("status", resp.GetStatus().String()))
	}
}
