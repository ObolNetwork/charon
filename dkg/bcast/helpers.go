// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	protocolIDPrefix = "/charon/dkg/bcast/1.0.0"
	protocolIDSig    = protocolIDPrefix + "/sig"
	protocolIDMsg    = protocolIDPrefix + "/msg"
	receiveTimeout   = time.Minute                    // Allow for peers to be out of sync, with some sending messages much earlier and having to wait.
	sendTimeout      = receiveTimeout + 2*time.Second // Allow for server to timeout first.
)

// hashFunc is a function that hashes a any-wrapped protobuf message.
type hashFunc func(*anypb.Any) ([]byte, error)

// Callback is a function that is called when a reliably-broadcast message was successfully received.
type Callback func(ctx context.Context, peerID peer.ID, msgID string, msg proto.Message) error

// CheckMessage is a function that ensures that msg is of the type that a given message ID should handle.
type CheckMessage func(ctx context.Context, peerID peer.ID, msgAny *anypb.Any) error

// signFunc is a function that signs a hash.
type signFunc func(msgID string, hash []byte) ([]byte, error)

// verifyFunc is a function that verifies a message and its signatures.
type verifyFunc func(string, *anypb.Any, [][]byte) error

// BroadcastFunc is a function that reliably-broadcasts a message to all peers (excluding self).
type BroadcastFunc func(ctx context.Context, msgID string, msg proto.Message) error
