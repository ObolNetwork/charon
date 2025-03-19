// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
)

func TestGetName(t *testing.T) {
	enrStr := "enr:-JG4QKXiqTRo5OmRPutHAjW93YAL0eo63NKDHTb2viARXiYaCJZXZeiT3-STunsuvTRxwP8G8CmhSvQLYqdqfZ8kL3aGAYDhssjugmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQOFWExWolIvyowQNrlUAIGqnBaHJexfLJE6zyFcovULYoN0Y3CCPoODdWRwgj6E"
	record, err := enr.Parse(enrStr)
	require.NoError(t, err)

	p1, err := p2p.NewPeerFromENR(record, 0)
	require.NoError(t, err)

	require.Equal(t, p1.Name, "wrong-council")
}
