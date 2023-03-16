// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

import (
	"context"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	protocolIDPrefix = "/charon/dkg/bcast/1.0.0"
	protocolIDSig    = protocolIDPrefix + "/sig"
	protocolIDMsg    = protocolIDPrefix + "/msg"
)

// HashFunc is a function that hashes a any-wrapped protobuf message.
type HashFunc func(*anypb.Any) ([]byte, error)

// Callback is a function that is called when a reliably-broadcast message was successfully received.
type Callback func(context.Context, proto.Message) error

// SignFunc is a function that signs a hash.
type SignFunc func(hash []byte) ([]byte, error)

// VerifyFunc is a function that verifies a message and its signatures.
type VerifyFunc func(*anypb.Any, [][]byte) (bool, error)
