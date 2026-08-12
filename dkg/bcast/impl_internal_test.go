// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestNewHashAny(t *testing.T) {
	anyPB := &anypb.Any{TypeUrl: "typeURL", Value: []byte("value")}

	hash := func(session []byte, msgID string, anyPB *anypb.Any) []byte {
		h, err := newHashAny(session)(msgID, anyPB)
		require.NoError(t, err)

		return h
	}

	base := hash([]byte("session"), "msgID", anyPB)

	// Deterministic.
	require.Equal(t, base, hash([]byte("session"), "msgID", anyPB))

	// Sensitive to each field.
	require.NotEqual(t, base, hash([]byte("other session"), "msgID", anyPB))
	require.NotEqual(t, base, hash([]byte("session"), "other msgID", anyPB))
	require.NotEqual(t, base, hash([]byte("session"), "msgID", &anypb.Any{TypeUrl: "other typeURL", Value: []byte("value")}))
	require.NotEqual(t, base, hash([]byte("session"), "msgID", &anypb.Any{TypeUrl: "typeURL", Value: []byte("other value")}))

	// Length prefixes prevent ambiguous concatenation of adjacent fields.
	require.NotEqual(t,
		hash([]byte("sessionX"), "msgID", anyPB),
		hash([]byte("session"), "XmsgID", anyPB),
	)
	require.NotEqual(t,
		hash([]byte("session"), "msgIDX", anyPB),
		hash([]byte("session"), "msgID", &anypb.Any{TypeUrl: "XtypeURL", Value: []byte("value")}),
	)
}
