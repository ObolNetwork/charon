// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"
	"github.com/test-go/testify/mock"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus/protocols"
	"github.com/obolnetwork/charon/core/mocks"
)

func TestNewConsensusWrapper(t *testing.T) {
	ctx := context.Background()
	randaoDuty := core.NewRandaoDuty(123)
	dataSet := core.UnsignedDataSet{}

	impl := mocks.NewConsensus(t)
	impl.On("ProtocolID").Return(protocol.ID(protocols.QBFTv2ProtocolID))
	impl.On("Start", ctx).Return()
	impl.On("Participate", ctx, randaoDuty).Return(nil)
	impl.On("Propose", ctx, randaoDuty, dataSet).Return(nil)
	impl.On("Subscribe", mock.Anything).Return()

	wrapped := newConsensusWrapper(impl)
	require.NotNil(t, wrapped)

	require.EqualValues(t, protocols.QBFTv2ProtocolID, wrapped.ProtocolID())

	wrapped.Start(ctx)

	err := wrapped.Participate(ctx, randaoDuty)
	require.NoError(t, err)

	err = wrapped.Propose(ctx, randaoDuty, dataSet)
	require.NoError(t, err)

	wrapped.Subscribe(func(ctx context.Context, d core.Duty, uds core.UnsignedDataSet) error {
		return nil
	})

	impl2 := mocks.NewConsensus(t)
	impl2.On("ProtocolID").Return(protocol.ID("foobar"))

	wrapped.SetImpl(impl2)

	require.EqualValues(t, "foobar", wrapped.ProtocolID())
}
