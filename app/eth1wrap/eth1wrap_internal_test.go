// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth1wrap

import (
	"context"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth1wrap/mocks"
)

func TestSetClient(t *testing.T) {
	client := &Client{
		addr:        "http://localhost:8545",
		reconnectCh: make(chan struct{}, 1),
	}

	mockEth1Client := mocks.NewEth1Client(t)
	client.setClient(mockEth1Client)

	require.Equal(t, mockEth1Client, client.eth1client, "Client should be set correctly")
}

func TestCloseClient(t *testing.T) {
	mockEth1Client := mocks.NewEth1Client(t)
	mockEth1Client.On("Close").Return().Once()

	client := &Client{
		addr:        "http://localhost:8545",
		eth1client:  mockEth1Client,
		reconnectCh: make(chan struct{}, 1),
	}

	client.closeClient()

	require.Nil(t, client.eth1client, "Client should be nil after closing")
	mockEth1Client.AssertExpectations(t)
}

func TestMaybeReconnect(t *testing.T) {
	client := &Client{
		addr:        "http://localhost:8545",
		reconnectCh: make(chan struct{}, 1),
	}

	// Check that reconnectCh is empty
	require.Empty(t, client.reconnectCh, "reconnectCh should be empty initially")

	// Trigger reconnect
	client.maybeReconnect()

	// Check that reconnectCh has a value
	require.Len(t, client.reconnectCh, 1, "reconnectCh should have a value after maybeReconnect")
}

func TestCheckClientIsAlive(t *testing.T) {
	t.Run("client_is_nil", func(t *testing.T) {
		client := &Client{
			addr:        "http://localhost:8545",
			eth1client:  nil,
			reconnectCh: make(chan struct{}, 1),
		}

		isAlive := client.checkClientIsAlive(context.Background())
		require.False(t, isAlive, "Client should not be alive when nil")
	})

	t.Run("client_is_alive", func(t *testing.T) {
		mockEth1Client := mocks.NewEth1Client(t)
		mockEth1Client.On("BlockNumber", mock.Anything).Return(uint64(12345), nil)

		client := &Client{
			addr:        "http://localhost:8545",
			eth1client:  mockEth1Client,
			reconnectCh: make(chan struct{}, 1),
		}

		isAlive := client.checkClientIsAlive(context.Background())
		require.True(t, isAlive, "Client should be alive when BlockNumber succeeds")
		mockEth1Client.AssertExpectations(t)
	})

	t.Run("client_is_not_alive", func(t *testing.T) {
		mockEth1Client := mocks.NewEth1Client(t)
		mockEth1Client.On("BlockNumber", mock.Anything).Return(uint64(0), errors.New("connection error"))

		client := &Client{
			addr:        "http://localhost:8545",
			eth1client:  mockEth1Client,
			reconnectCh: make(chan struct{}, 1),
		}

		isAlive := client.checkClientIsAlive(context.Background())
		require.False(t, isAlive, "Client should not be alive when BlockNumber fails")
		mockEth1Client.AssertExpectations(t)
	})
}

func TestMagicValue(t *testing.T) {
	// Test that the magic value constant is correct
	expectedMagicValue := [4]byte{0x16, 0x26, 0xba, 0x7e}
	require.Equal(t, expectedMagicValue, erc1271MagicValue, "Magic value should match ERC-1271 specification")
}

func TestERC1271Implementation(t *testing.T) {
	mockEth1Client := mocks.NewEth1Client(t)
	mockEth1Client.On("Close").Return().Maybe()

	mockErc1271 := mocks.NewErc1271(t)
	mockErc1271.On("IsValidSignature", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			opts := args.Get(0).(*bind.CallOpts)
			hash := args.Get(1).([32]byte)
			sig := args.Get(2).([]byte)

			require.Nil(t, opts, "Opts should be nil")
			require.Equal(t, [32]byte{1, 2, 3}, hash, "Hash should be passed correctly")
			require.Equal(t, []byte{4, 5, 6}, sig, "Signature should be passed correctly")
		}).
		Return(erc1271MagicValue, nil).Once()

	client := NewEth1Client(
		"http://localhost:8545",
		func(ctx context.Context, rawurl string) (Eth1Client, error) {
			return mockEth1Client, nil
		},
		func(contractAddress string, eth1Client Eth1Client) (Erc1271, error) {
			require.Equal(t, "0x123", contractAddress, "Contract address should be passed to factory")
			require.Equal(t, mockEth1Client, eth1Client, "Eth1Client should be passed to factory")

			return mockErc1271, nil
		},
	)

	// Start the client
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = client.Run(ctx)
	}()

	// Wait for client to initialize
	time.Sleep(100 * time.Millisecond)

	hash := [32]byte{1, 2, 3}
	sig := []byte{4, 5, 6}
	valid, err := client.VerifySmartContractBasedSignature("0x123", hash, sig)

	require.NoError(t, err, "Should not return an error")
	require.True(t, valid, "Signature should be valid")

	mockEth1Client.AssertExpectations(t)
	mockErc1271.AssertExpectations(t)
}
