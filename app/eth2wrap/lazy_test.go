// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"context"
	"testing"

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
