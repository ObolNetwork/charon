// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package testutil

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/log"
)

// RequireNoError extends require.NoError with additional error stack trace and
// structured field logging for improved test debugging.
func RequireNoError(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		return
	}

	log.Error(context.Background(), "Unexpected test error", err)
	require.NoErrorf(t, err, "See error log above for more info")
}

// RequireProtoEqual compares two protobuf messages and fails the test if they
// are not equal. It uses prototext.Format to print the messages in a human
// readable format.
func RequireProtoEqual(t *testing.T, a, b proto.Message) {
	t.Helper()

	if proto.Equal(a, b) {
		return
	}

	require.Fail(t, "Protobuf messages not equal",
		"expected: %s\nactual: %v", prototext.Format(a), prototext.Format(b))
}

// RequireProtosEqual compares two protobuf slices and fails the test if they
// are not equal. It uses prototext.Format to print the messages in a human
// readable format.
func RequireProtosEqual[P proto.Message](t *testing.T, a, b []P) {
	t.Helper()

	if len(a) != len(b) {
		require.Fail(t, "Protobuf slices length not equal",
			"expected: %s\nactual: %v", len(a), len(b))
	}

	for i := 0; i < len(a); i++ {
		RequireProtoEqual(t, a[i], b[i])
	}
}
