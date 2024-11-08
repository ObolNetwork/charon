// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff_test

import (
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core/hotstuff"
)

func TestTransport(t *testing.T) {
	const nodes = 3

	transport := hotstuff.NewTransport[string](nodes)

	err := transport.Broadcast(context.Background(), "bcast")
	require.NoError(t, err)

	for n := range nodes {
		ch, err := transport.ReceiveCh(hotstuff.ID(n + 1))
		require.NoError(t, err)

		m := <-ch
		require.Equal(t, "bcast", m)

		if n > 0 {
			val := strconv.FormatInt(int64(n), 10)
			err := transport.SendTo(context.Background(), hotstuff.ID(1), val)
			require.NoError(t, err)
		}
	}

	ch, err := transport.ReceiveCh(hotstuff.ID(1))
	require.NoError(t, err)

	for n := 1; n < nodes; n++ {
		expect := strconv.FormatInt(int64(n), 10)
		m := <-ch
		require.Equal(t, expect, m)
	}

	t.Run("invalid replica id", func(t *testing.T) {
		err := transport.SendTo(context.Background(), hotstuff.ID(nodes+1), "invalid")
		require.Equal(t, hotstuff.ErrInvalidReplicaID, err)

		_, err = transport.ReceiveCh(hotstuff.ID(nodes + 1))
		require.Equal(t, hotstuff.ErrInvalidReplicaID, err)
	})
}
