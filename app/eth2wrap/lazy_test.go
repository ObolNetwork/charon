// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"context"
	"net/http"
	"testing"

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
	proposerDutiesCache := func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) (eth2wrap.ProposerDutyWithMeta, error) {
		return eth2wrap.ProposerDutyWithMeta{}, nil
	}
	attesterDutiesCache := func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) (eth2wrap.AttesterDutyWithMeta, error) {
		return eth2wrap.AttesterDutyWithMeta{}, nil
	}
	syncDutiesCache := func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) (eth2wrap.SyncDutyWithMeta, error) {
		return eth2wrap.SyncDutyWithMeta{}, nil
	}

	client := mocks.NewClient(t)
	client.On("SetDutiesCache", mock.Anything, mock.Anything, mock.Anything).Once()

	l := eth2wrap.NewLazyForT(client)
	l.SetDutiesCache(proposerDutiesCache, attesterDutiesCache, syncDutiesCache)
}

func TestLazy_ProposerDutiesCache(t *testing.T) {
	ctx := context.Background()
	proposerDuties := eth2wrap.ProposerDutyWithMeta{}

	client := mocks.NewClient(t)
	client.On("ProposerDutiesCache", ctx, eth2p0.Epoch(0), []eth2p0.ValidatorIndex{}).Return(proposerDuties, nil).Once()

	l := eth2wrap.NewLazyForT(client)

	proposerDuties2, err := l.ProposerDutiesCache(ctx, 0, []eth2p0.ValidatorIndex{})
	require.NoError(t, err)
	require.Equal(t, proposerDuties, proposerDuties2)
}

func TestLazy_AttesterDutiesCache(t *testing.T) {
	ctx := context.Background()
	attesterDuties := eth2wrap.AttesterDutyWithMeta{}

	client := mocks.NewClient(t)
	client.On("AttesterDutiesCache", ctx, eth2p0.Epoch(0), []eth2p0.ValidatorIndex{}).Return(attesterDuties, nil).Once()

	l := eth2wrap.NewLazyForT(client)

	attesterDuties2, err := l.AttesterDutiesCache(ctx, 0, []eth2p0.ValidatorIndex{})
	require.NoError(t, err)
	require.Equal(t, attesterDuties, attesterDuties2)
}

func TestLazy_SyncDutiesCache(t *testing.T) {
	ctx := context.Background()
	syncDuties := eth2wrap.SyncDutyWithMeta{}

	client := mocks.NewClient(t)
	client.On("SyncCommDutiesCache", ctx, eth2p0.Epoch(0), []eth2p0.ValidatorIndex{}).Return(syncDuties, nil).Once()

	l := eth2wrap.NewLazyForT(client)

	syncDuties2, err := l.SyncCommDutiesCache(ctx, 0, []eth2p0.ValidatorIndex{})
	require.NoError(t, err)
	require.Equal(t, syncDuties, syncDuties2)
}
