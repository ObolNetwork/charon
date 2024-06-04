// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"context"
	"errors"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/eth2wrap/mocks"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
)

func TestMulti_Name(t *testing.T) {
	client := mocks.NewClient(t)

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client})

	require.Equal(t, "eth2wrap.multi", m.Name())
}

func TestMulti_Address(t *testing.T) {
	client := mocks.NewClient(t)
	client.On("Address").Return("test").Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client})

	require.Equal(t, "test", m.Address())
}

func TestMulti_IsActive(t *testing.T) {
	client1 := mocks.NewClient(t)
	client1.On("IsActive").Return(false).Once()
	client2 := mocks.NewClient(t)
	client2.On("IsActive").Return(true).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client1, client2})

	require.True(t, m.IsActive())
}

func TestMulti_IsSynced(t *testing.T) {
	client1 := mocks.NewClient(t)
	client1.On("IsSynced").Return(false).Once()
	client2 := mocks.NewClient(t)
	client2.On("IsSynced").Return(true).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client1, client2})

	require.True(t, m.IsSynced())
}

func TestMulti_NodePeerCount(t *testing.T) {
	client := mocks.NewClient(t)
	client.On("Address").Return("test").Once()
	client.On("NodePeerCount", mock.Anything).Return(5, nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client})

	c, err := m.NodePeerCount(context.Background())
	require.NoError(t, err)
	require.Equal(t, 5, c)

	expectedErr := errors.New("boo")
	client.On("NodePeerCount", mock.Anything).Return(0, expectedErr).Once()
	_, err = m.NodePeerCount(context.Background())
	require.ErrorIs(t, err, expectedErr)
}

func TestMulti_BlockAttestations(t *testing.T) {
	ctx := context.Background()
	atts := make([]*eth2p0.Attestation, 3)

	client := mocks.NewClient(t)
	client.On("Address").Return("test").Once()
	client.On("BlockAttestations", mock.Anything, "state").Return(atts, nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client})

	atts2, err := m.BlockAttestations(ctx, "state")
	require.NoError(t, err)
	require.Equal(t, atts, atts2)

	expectedErr := errors.New("boo")
	client.On("BlockAttestations", mock.Anything, "state").Return(nil, expectedErr).Once()
	_, err = m.BlockAttestations(ctx, "state")
	require.ErrorIs(t, err, expectedErr)
}

func TestMulti_AggregateSyncCommitteeSelections(t *testing.T) {
	ctx := context.Background()
	partsel := make([]*eth2exp.SyncCommitteeSelection, 1)
	selections := make([]*eth2exp.SyncCommitteeSelection, 3)

	client := mocks.NewClient(t)
	client.On("Address").Return("test").Once()
	client.On("AggregateSyncCommitteeSelections", mock.Anything, partsel).Return(selections, nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client})

	selections2, err := m.AggregateSyncCommitteeSelections(ctx, partsel)
	require.NoError(t, err)
	require.Equal(t, selections, selections2)

	expectedErr := errors.New("boo")
	client.On("AggregateSyncCommitteeSelections", mock.Anything, partsel).Return(nil, expectedErr).Once()
	_, err = m.AggregateSyncCommitteeSelections(ctx, partsel)
	require.ErrorIs(t, err, expectedErr)
}

func TestMulti_AggregateBeaconCommitteeSelections(t *testing.T) {
	ctx := context.Background()
	partsel := make([]*eth2exp.BeaconCommitteeSelection, 1)
	selections := make([]*eth2exp.BeaconCommitteeSelection, 3)

	client := mocks.NewClient(t)
	client.On("Address").Return("test").Once()
	client.On("AggregateBeaconCommitteeSelections", mock.Anything, partsel).Return(selections, nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client})

	selections2, err := m.AggregateBeaconCommitteeSelections(ctx, partsel)
	require.NoError(t, err)
	require.Equal(t, selections, selections2)

	expectedErr := errors.New("boo")
	client.On("AggregateBeaconCommitteeSelections", mock.Anything, partsel).Return(nil, expectedErr).Once()
	_, err = m.AggregateBeaconCommitteeSelections(ctx, partsel)
	require.ErrorIs(t, err, expectedErr)
}

func TestMulti_ProposerConfig(t *testing.T) {
	ctx := context.Background()
	resp := &eth2exp.ProposerConfigResponse{}

	client := mocks.NewClient(t)
	client.On("Address").Return("test").Once()
	client.On("ProposerConfig", mock.Anything).Return(resp, nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client})

	resp2, err := m.ProposerConfig(ctx)
	require.NoError(t, err)
	require.Equal(t, resp, resp2)

	expectedErr := errors.New("boo")
	client.On("ProposerConfig", mock.Anything).Return(nil, expectedErr).Once()
	_, err = m.ProposerConfig(ctx)
	require.ErrorIs(t, err, expectedErr)
}

func TestMulti_ActiveValidators(t *testing.T) {
	ctx := context.Background()
	vals := make(eth2wrap.ActiveValidators)

	client := mocks.NewClient(t)
	client.On("ActiveValidators", mock.Anything).Return(vals, nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client})

	vals2, err := m.ActiveValidators(ctx)
	require.NoError(t, err)
	require.Equal(t, vals, vals2)

	expectedErr := errors.New("boo")
	client.On("ActiveValidators", mock.Anything).Return(nil, expectedErr).Once()
	_, err = m.ActiveValidators(ctx)
	require.ErrorIs(t, err, expectedErr)
}

func TestMulti_SetValidatorCache(t *testing.T) {
	valCache := func(context.Context) (eth2wrap.ActiveValidators, eth2wrap.CompleteValidators, error) {
		return nil, nil, nil
	}

	client := mocks.NewClient(t)
	client.On("SetValidatorCache", mock.Anything).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client})
	m.SetValidatorCache(valCache)
}
