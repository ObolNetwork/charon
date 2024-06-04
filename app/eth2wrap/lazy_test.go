// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"context"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/eth2wrap/mocks"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
)

func TestLazy_Name(t *testing.T) {
	client := mocks.NewClient(t)
	client.On("Name").Return("test").Once()

	l := eth2wrap.NewLazyForT(client)

	require.Equal(t, "test", l.Name())
}

func TestLazy_Address(t *testing.T) {
	client := mocks.NewClient(t)
	client.On("Address").Return("test").Once()

	l := eth2wrap.NewLazyForT(client)

	require.Equal(t, "test", l.Address())
}

func TestLazy_IsActive(t *testing.T) {
	client := mocks.NewClient(t)
	client.On("IsActive").Return(true).Once()

	l := eth2wrap.NewLazyForT(client)

	require.True(t, l.IsActive())
}

func TestLazy_IsSynced(t *testing.T) {
	client := mocks.NewClient(t)
	client.On("IsSynced").Return(true).Once()

	l := eth2wrap.NewLazyForT(client)

	require.True(t, l.IsSynced())
}

func TestLazy_NodePeerCount(t *testing.T) {
	client := mocks.NewClient(t)
	client.On("NodePeerCount", mock.Anything).Return(5, nil).Once()

	l := eth2wrap.NewLazyForT(client)

	c, err := l.NodePeerCount(context.Background())
	require.NoError(t, err)
	require.Equal(t, 5, c)
}

func TestLazy_BlockAttestations(t *testing.T) {
	ctx := context.Background()
	atts := make([]*eth2p0.Attestation, 3)

	client := mocks.NewClient(t)
	client.On("BlockAttestations", ctx, "state").Return(atts, nil).Once()

	l := eth2wrap.NewLazyForT(client)

	atts2, err := l.BlockAttestations(ctx, "state")
	require.NoError(t, err)
	require.Equal(t, atts, atts2)
}

func TestLazy_AggregateSyncCommitteeSelections(t *testing.T) {
	ctx := context.Background()
	partsel := make([]*eth2exp.SyncCommitteeSelection, 1)
	selections := make([]*eth2exp.SyncCommitteeSelection, 3)

	client := mocks.NewClient(t)
	client.On("AggregateSyncCommitteeSelections", ctx, partsel).Return(selections, nil).Once()

	l := eth2wrap.NewLazyForT(client)

	selections2, err := l.AggregateSyncCommitteeSelections(ctx, partsel)
	require.NoError(t, err)
	require.Equal(t, selections, selections2)
}

func TestLazy_AggregateBeaconCommitteeSelections(t *testing.T) {
	ctx := context.Background()
	partsel := make([]*eth2exp.BeaconCommitteeSelection, 1)
	selections := make([]*eth2exp.BeaconCommitteeSelection, 3)

	client := mocks.NewClient(t)
	client.On("AggregateBeaconCommitteeSelections", ctx, partsel).Return(selections, nil).Once()

	l := eth2wrap.NewLazyForT(client)

	selections2, err := l.AggregateBeaconCommitteeSelections(ctx, partsel)
	require.NoError(t, err)
	require.Equal(t, selections, selections2)
}

func TestLazy_ProposerConfig(t *testing.T) {
	ctx := context.Background()
	resp := &eth2exp.ProposerConfigResponse{}

	client := mocks.NewClient(t)
	client.On("ProposerConfig", ctx).Return(resp, nil).Once()

	l := eth2wrap.NewLazyForT(client)

	resp2, err := l.ProposerConfig(ctx)
	require.NoError(t, err)
	require.Equal(t, resp, resp2)
}

func TestLazy_ActiveValidators(t *testing.T) {
	ctx := context.Background()
	vals := make(eth2wrap.ActiveValidators)

	client := mocks.NewClient(t)
	client.On("ActiveValidators", ctx).Return(vals, nil).Once()

	l := eth2wrap.NewLazyForT(client)

	vals2, err := l.ActiveValidators(ctx)
	require.NoError(t, err)
	require.Equal(t, vals, vals2)
}

func TestLazy_SetValidatorCache(t *testing.T) {
	valCache := func(context.Context) (eth2wrap.ActiveValidators, eth2wrap.CompleteValidators, error) {
		return nil, nil, nil
	}

	client := mocks.NewClient(t)
	client.On("SetValidatorCache", mock.Anything).Once()

	l := eth2wrap.NewLazyForT(client)
	l.SetValidatorCache(valCache)
}
