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

	recvChannels := make([]chan *hotstuff.Msg, total)
	for i := range recvChannels {
		recvChannels[i] = make(chan *hotstuff.Msg, ioBufferSize)
	}
	transports := make([]hotstuff.Transport, total)
	for i := range transports {
		transports[i] = newTransport(recvChannels, recvChannels[i])
	}

	replicas := make([]*hotstuff.Replica, total)
	for i := range total {
		id := hotstuff.ID(i + 1)
		replicas[i] = hotstuff.NewReplica(id, cluster, transports[i], phaseTimeout)
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
