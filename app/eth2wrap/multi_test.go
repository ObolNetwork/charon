// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/eth2wrap/mocks"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
)

func TestMulti_Name(t *testing.T) {
	client := mocks.NewClient(t)

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)

	require.Equal(t, "eth2wrap.multi", m.Name())
}

func TestMulti_Address(t *testing.T) {
	client := mocks.NewClient(t)
	client.On("Address").Return("test").Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)

	require.Equal(t, "test", m.Address())
}

func TestMulti_IsActive(t *testing.T) {
	client1 := mocks.NewClient(t)
	client1.On("IsActive").Return(false).Once()

	client2 := mocks.NewClient(t)
	client2.On("IsActive").Return(true).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client1, client2}, nil)

	require.True(t, m.IsActive())
}

func TestMulti_IsSynced(t *testing.T) {
	client1 := mocks.NewClient(t)
	client1.On("IsSynced").Return(false).Once()

	client2 := mocks.NewClient(t)
	client2.On("IsSynced").Return(true).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client1, client2}, nil)

	require.True(t, m.IsSynced())
}

func TestMulti_ProposerConfig(t *testing.T) {
	ctx := context.Background()
	resp := &eth2exp.ProposerConfigResponse{}

	client := mocks.NewClient(t)
	client.On("Address").Return("test").Once()
	client.On("ProposerConfig", mock.Anything).Return(resp, nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)

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

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)

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

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)
	m.SetValidatorCache(valCache)
}
