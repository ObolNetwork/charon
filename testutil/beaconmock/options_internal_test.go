// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package beaconmock

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStubRoot(t *testing.T) {
	root := mustRoot(1)
	require.Equal(t, "0x0100000000000000000000000000000000000000000000000000000000000000", fmt.Sprintf("%#x", root))
}
