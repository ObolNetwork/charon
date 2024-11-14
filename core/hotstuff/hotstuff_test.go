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

	inputValue := []byte("hotstuff")
	outputCh := make(chan hotstuff.Value, total)

	cluster, err := newCluster(total, threshold)
	require.NoError(t, err)

	recvChannels := make([]chan *hotstuff.Msg, total)
	for i := range recvChannels {
		recvChannels[i] = make(chan *hotstuff.Msg, ioBufferSize)
	}
	transports := make([]hotstuff.Transport, total)
	for i := range transports {
		transports[i] = newTransport(recvChannels, recvChannels[i])
	}

	decidedFunc := func(value hotstuff.Value, _ hotstuff.View) {
		outputCh <- value
	}

	replicas := make([]*hotstuff.Replica, total)
	for i := range total {
		id := hotstuff.NewIDFromIndex(i)
		privateKey := cluster.privateKeys[i]
		replicas[i] = hotstuff.NewReplica(id, cluster, transports[i], privateKey, decidedFunc, inputValue, phaseTimeout)
	}

	ctx, cancel := context.WithCancel(context.Background())
	wg := sync.WaitGroup{}
	wg.Add(total)

	for i := range total {
		go replicas[i].Run(ctx, wg.Done)
	}

	for range total {
		value := <-outputCh
		require.EqualValues(t, inputValue, value)
	}

	// Stop all processes
	cancel()
	wg.Wait()
}

func TestPhaseString(t *testing.T) {
	tests := []struct {
		p    hotstuff.Phase
		pstr string
	}{
		{hotstuff.PreparePhase, "prepare"},
		{hotstuff.PreCommitPhase, "pre_commit"},
		{hotstuff.CommitPhase, "commit"},
		{hotstuff.DecidePhase, "decide"},
		{hotstuff.TerminalPhase, "terminal"},
	}

	for _, tt := range tests {
		t.Run(tt.pstr, func(t *testing.T) {
			require.Equal(t, tt.pstr, tt.p.String())
		})
	}
}

func TestNextPhase(t *testing.T) {
	tests := []struct {
		p    hotstuff.Phase
		next hotstuff.Phase
	}{
		{hotstuff.PreparePhase, hotstuff.PreCommitPhase},
		{hotstuff.PreCommitPhase, hotstuff.CommitPhase},
		{hotstuff.CommitPhase, hotstuff.DecidePhase},
		{hotstuff.DecidePhase, hotstuff.TerminalPhase},
		{hotstuff.TerminalPhase, hotstuff.TerminalPhase},
	}

	for _, tt := range tests {
		t.Run(tt.p.String(), func(t *testing.T) {
			require.Equal(t, tt.next, tt.p.NextPhase())
		})
	}
}

func TestIDToIndex(t *testing.T) {
	require.Equal(t, 0, hotstuff.ID(1).ToIndex())
	require.Equal(t, 1, hotstuff.ID(2).ToIndex())
}

func TestNewIDFromIndex(t *testing.T) {
	require.Equal(t, hotstuff.ID(1), hotstuff.NewIDFromIndex(0))
	require.Equal(t, hotstuff.ID(2), hotstuff.NewIDFromIndex(1))
}
