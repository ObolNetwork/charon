// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	client.On("Name").Return("test")

	l := eth2wrap.NewLazyForT(client)

	require.Equal(t, "test", l.Name())
}

func TestLazy_Address(t *testing.T) {
	client := mocks.NewClient(t)
	client.On("Address").Return("test")

	l := eth2wrap.NewLazyForT(client)

	require.Equal(t, "test", l.Address())
}

func TestLazy_IsActive(t *testing.T) {
	client := mocks.NewClient(t)
	client.On("IsActive").Return(true)

	l := eth2wrap.NewLazyForT(client)

	require.True(t, l.IsActive())
}

func TestLazy_IsSynced(t *testing.T) {
	client := mocks.NewClient(t)
	client.On("IsSynced").Return(true)

	l := eth2wrap.NewLazyForT(client)

	require.True(t, l.IsSynced())
}

func TestLazy_NodePeerCount(t *testing.T) {
	client := mocks.NewClient(t)
	client.On("NodePeerCount", mock.Anything).Return(5, nil)

	l := eth2wrap.NewLazyForT(client)

	c, err := l.NodePeerCount(context.Background())
	require.NoError(t, err)
	require.Equal(t, 5, c)
}
