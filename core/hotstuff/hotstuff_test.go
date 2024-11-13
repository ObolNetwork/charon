// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core/hotstuff"
)

func TestHotStuff(t *testing.T) {
	const (
		total        = 4
		threshold    = 3
		phaseTimeout = 100 * time.Millisecond
	)

	inputCh := make(chan hotstuff.Value)
	outputCh := make(chan hotstuff.Value, total)

	cluster, err := hotstuff.NewCluster(total, threshold, inputCh, outputCh)
	require.NoError(t, err)

	transport := hotstuff.NewTransport[hotstuff.Msg](total)

	replicas := make([]*hotstuff.Replica, total)
	for i := range total {
		id := hotstuff.ID(i + 1)
		replicas[i], err = hotstuff.NewReplica(id, cluster, transport, phaseTimeout)
		require.NoError(t, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	wg := sync.WaitGroup{}
	wg.Add(total)

	for i := range total {
		go replicas[i].Run(ctx, wg.Done)
	}

	// The value to be replicated
	inputCh <- []byte("hotstuff")

	for range total {
		value := <-outputCh
		require.EqualValues(t, "hotstuff", value)
	}

	// Stop all processes
	cancel()
	wg.Wait()
}
