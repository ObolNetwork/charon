// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/hotstuff"
	"github.com/obolnetwork/charon/core/hotstuff/mocks"
)

func TestHotStuff(t *testing.T) {
	const (
		total     = 4
		threshold = 3
	)

	inputValue := []byte("hotstuff")
	outputCh := make(chan hotstuff.Value, total)

	cluster, err := newCluster(total, threshold, 1, 1000)
	require.NoError(t, err)

	recvChannels := make([]chan *hotstuff.Msg, total)
	for i := range recvChannels {
		recvChannels[i] = make(chan *hotstuff.Msg, ioBufferSize)
	}
	transports := make([]hotstuff.Transport, total)
	for i := range transports {
		transports[i] = newTransport(recvChannels, recvChannels[i])
	}

	mutedTransport := mocks.NewTransport(t)
	mutedTransport.On("Broadcast", mock.Anything, mock.Anything).Return(nil).Maybe()
	mutedTransport.On("SendTo", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	transports[0] = mutedTransport

	decidedFunc := func(value hotstuff.Value, _ core.Duty, _ hotstuff.View) {
		outputCh <- value
	}

	valueCh := make(chan hotstuff.Value, 1)
	valueCh <- inputValue

	duty := core.NewProposerDuty(1)

	replicas := make([]*hotstuff.Replica, total)
	for i := range total {
		privateKey := cluster.privateKeys[i]
		receiveCh := recvChannels[i]
		replicas[i] = hotstuff.NewReplica(
			hotstuff.ID(i), duty, cluster, []hotstuff.ID{},
			transports[i], receiveCh, privateKey, decidedFunc, valueCh)
	}

	group, ctx := errgroup.WithContext(context.Background())

	for i := range total {
		group.Go(func() error {
			return replicas[i].Run(ctx)
		})
	}

	for range total {
		value := <-outputCh
		require.EqualValues(t, inputValue, value)
	}

	err = group.Wait()
	require.NoError(t, err)
}

func TestHotStuffTimeout(t *testing.T) {
	const (
		total     = 3
		threshold = 3
		maxView   = 2
	)

	cluster, err := newCluster(total, threshold, maxView, 100)
	require.NoError(t, err)

	duty := core.NewProposerDuty(1)
	decidedFunc := func(hotstuff.Value, core.Duty, hotstuff.View) {}
	valueCh := make(chan hotstuff.Value)

	recvChannels := make([]chan *hotstuff.Msg, total)
	for i := range recvChannels {
		recvChannels[i] = make(chan *hotstuff.Msg, ioBufferSize)
	}

	var newViewMsgCounter atomic.Int64

	replicas := make([]*hotstuff.Replica, total)
	for i := range total {
		mutedTransport := mocks.NewTransport(t)
		mutedTransport.On("Broadcast", mock.Anything, mock.Anything).Return(nil).Maybe()
		mutedTransport.On("SendTo", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
			msg := args.Get(2).(*hotstuff.Msg)
			if msg.Type == hotstuff.MsgNewView {
				newViewMsgCounter.Add(1)
			}
		}).Return(nil).Maybe()

		privateKey := cluster.privateKeys[i]
		receiveCh := recvChannels[i]
		replicas[i] = hotstuff.NewReplica(
			hotstuff.ID(i), duty, cluster, []hotstuff.ID{},
			mutedTransport, receiveCh, privateKey, decidedFunc, valueCh)
	}

	group, ctx := errgroup.WithContext(context.Background())

	for i := range total {
		group.Go(func() error {
			return replicas[i].Run(ctx)
		})
	}

	err = group.Wait()
	require.ErrorIs(t, err, hotstuff.ErrMaxViewReached)

	require.EqualValues(t, total*maxView, newViewMsgCounter.Load())
}

func TestHotStuffNoLeaderAvailable(t *testing.T) {
	const (
		total     = 3
		threshold = 3
		maxView   = 2
	)

	cluster, err := newCluster(total, threshold, maxView, 100)
	require.NoError(t, err)

	duty := core.NewProposerDuty(1)
	decidedFunc := func(hotstuff.Value, core.Duty, hotstuff.View) {}
	valueCh := make(chan hotstuff.Value)

	recvChannels := make([]chan *hotstuff.Msg, total)
	for i := range recvChannels {
		recvChannels[i] = make(chan *hotstuff.Msg, ioBufferSize)
	}

	replicas := make([]*hotstuff.Replica, total)
	for i := range total {
		mutedTransport := mocks.NewTransport(t)
		mutedTransport.On("Broadcast", mock.Anything, mock.Anything).Return(nil).Maybe()
		mutedTransport.On("SendTo", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

		privateKey := cluster.privateKeys[i]
		receiveCh := recvChannels[i]
		replicas[i] = hotstuff.NewReplica(
			hotstuff.ID(i), duty, cluster, []hotstuff.ID{0, 1, 2}, // all unreachable
			mutedTransport, receiveCh, privateKey, decidedFunc, valueCh)
	}

	group, ctx := errgroup.WithContext(context.Background())

	for i := range total {
		group.Go(func() error {
			return replicas[i].Run(ctx)
		})
	}

	err = group.Wait()
	require.ErrorIs(t, err, hotstuff.ErrNoLeaderAvailable)
}

func TestHotStuffSkipUnreachableLeader(t *testing.T) {
	const (
		total     = 4
		threshold = 3
	)

	inputValue := []byte("hotstuff")
	outputCh := make(chan hotstuff.Value, total)

	cluster, err := newCluster(total, threshold, 1, 1000)
	require.NoError(t, err)

	recvChannels := make([]chan *hotstuff.Msg, total)
	for i := range recvChannels {
		recvChannels[i] = make(chan *hotstuff.Msg, ioBufferSize)
	}
	transports := make([]hotstuff.Transport, total)
	for i := range transports {
		transports[i] = newTransport(recvChannels, recvChannels[i])
	}

	decidedFunc := func(value hotstuff.Value, _ core.Duty, _ hotstuff.View) {
		outputCh <- value
	}

	valueCh := make(chan hotstuff.Value, 1)
	valueCh <- inputValue

	duty := core.NewProposerDuty(1)

	replicas := make([]*hotstuff.Replica, total)
	for i := range total {
		privateKey := cluster.privateKeys[i]
		receiveCh := recvChannels[i]
		replicas[i] = hotstuff.NewReplica(
			hotstuff.ID(i), duty, cluster, []hotstuff.ID{0, 1},
			transports[i], receiveCh, privateKey, decidedFunc, valueCh)
	}

	group, ctx := errgroup.WithContext(context.Background())

	for i := range total {
		group.Go(func() error {
			return replicas[i].Run(ctx)
		})
	}

	for range total {
		value := <-outputCh
		require.EqualValues(t, inputValue, value)
	}

	err = group.Wait()
	require.NoError(t, err)
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
