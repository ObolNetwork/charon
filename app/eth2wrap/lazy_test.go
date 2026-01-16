// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"context"
	"net/http"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/eth2wrap/mocks"
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

func TestLazy_Proxy(t *testing.T) {
	client := mocks.NewClient(t)
	client.On("Proxy", mock.Anything, mock.Anything).Return(nil, nil).Once()

	l := eth2wrap.NewLazyForT(client)

	req, err := http.NewRequest(http.MethodGet, "", nil)
	require.NoError(t, err)
	_, err = l.Proxy(t.Context(), req)
	require.NoError(t, err)
}

func TestLazy_ClientForAddress(t *testing.T) {
	innerClient := mocks.NewClient(t)
	scopedClient := mocks.NewClient(t)
	innerClient.On("ClientForAddress", "http://test:5051").Return(scopedClient).Once()

	l := eth2wrap.NewLazyForT(innerClient)

	result := l.ClientForAddress("http://test:5051")
	require.NotNil(t, result)
}

func TestLazy_SetDutiesCache(t *testing.T) {
	proposerDutiesCache := func(context.Context, eth2p0.Epoch) ([]*eth2v1.ProposerDuty, error) {
		return nil, nil
	}
	attesterDutiesCache := func(context.Context, eth2p0.Epoch) ([]*eth2v1.AttesterDuty, error) {
		return nil, nil
	}
	syncDutiesCache := func(context.Context, eth2p0.Epoch) ([]*eth2v1.SyncCommitteeDuty, error) {
		return nil, nil
	}

	client := mocks.NewClient(t)
	client.On("SetDutiesCache", mock.Anything, mock.Anything, mock.Anything).Once()

	l := eth2wrap.NewLazyForT(client)
	l.SetDutiesCache(proposerDutiesCache, attesterDutiesCache, syncDutiesCache)
}

func TestLazy_ProposerDutiesByEpoch(t *testing.T) {
	ctx := context.Background()
	proposerDuties := make([]*eth2v1.ProposerDuty, 0)

	client := mocks.NewClient(t)
	client.On("ProposerDutiesByEpoch", ctx, eth2p0.Epoch(0)).Return(proposerDuties, nil).Once()

	l := eth2wrap.NewLazyForT(client)

	proposerDuties2, err := l.ProposerDutiesByEpoch(ctx, 0)
	require.NoError(t, err)
	require.Equal(t, proposerDuties, proposerDuties2)
}

func TestLazy_AttesterDutiesByEpoch(t *testing.T) {
	ctx := context.Background()
	attesterDuties := make([]*eth2v1.AttesterDuty, 0)

	client := mocks.NewClient(t)
	client.On("AttesterDutiesByEpoch", ctx, eth2p0.Epoch(0)).Return(attesterDuties, nil).Once()

	l := eth2wrap.NewLazyForT(client)

	attesterDuties2, err := l.AttesterDutiesByEpoch(ctx, 0)
	require.NoError(t, err)
	require.Equal(t, attesterDuties, attesterDuties2)
}

func TestLazy_SyncDutiesByEpoch(t *testing.T) {
	ctx := context.Background()
	syncDuties := make([]*eth2v1.SyncCommitteeDuty, 0)

	client := mocks.NewClient(t)
	client.On("SyncDutiesByEpoch", ctx, eth2p0.Epoch(0)).Return(syncDuties, nil).Once()

	l := eth2wrap.NewLazyForT(client)

	syncDuties2, err := l.SyncDutiesByEpoch(ctx, 0)
	require.NoError(t, err)
	require.Equal(t, syncDuties, syncDuties2)
}

func TestLazy_UpdateCacheIndices(t *testing.T) {
	ctx := context.Background()

	client := mocks.NewClient(t)
	client.On("UpdateCacheIndices", ctx, []eth2p0.ValidatorIndex{}).Return().Once()

	l := eth2wrap.NewLazyForT(client)

	l.UpdateCacheIndices(ctx, []eth2p0.ValidatorIndex{})
}
