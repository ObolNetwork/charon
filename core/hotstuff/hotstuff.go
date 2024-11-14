// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import "context"

// Transport defines replica's transport layer.
type Transport interface {
	// Broadcast sends a message to all replicas, including itself.
	Broadcast(ctx context.Context, msg *Msg) error

	// SendTo sends a message to the specified replica, typically to the leader.
	SendTo(ctx context.Context, id ID, msg *Msg) error

	// ReceiveCh returns channel receiving inbound messages.
	ReceiveCh() <-chan *Msg
}
