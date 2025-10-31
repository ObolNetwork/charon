// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth1wrap

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth1wrap/mocks"
)

func TestSetClient(t *testing.T) {
	client := &client{
		reconnectCh: make(chan struct{}, 1),
	}

	newNativeClient := &ethclient.Client{}
	client.setClient(newNativeClient)

	require.Equal(t, newNativeClient, client.eth1client)
}

func TestCloseClient(t *testing.T) {
	ecMock := mocks.NewEthClient(t)
	ecMock.On("Close").Return().Once()

	client := &client{
		eth1client:  ecMock,
		reconnectCh: make(chan struct{}, 1),
	}

	client.close()

	require.Nil(t, client.eth1client, "Client should be nil after closing")
}

func TestMaybeReconnect(t *testing.T) {
	client := &client{
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
	ecMock := mocks.NewEthClient(t)

	t.Run("client is nil", func(t *testing.T) {
		client := &client{
			eth1client:  nil,
			reconnectCh: make(chan struct{}, 1),
		}

		isAlive := client.checkClientIsAlive(context.Background())
		require.False(t, isAlive, "Client should not be alive when nil")
	})

	t.Run("client is alive", func(t *testing.T) {
		ecMock.On("BlockNumber", mock.Anything).Return(uint64(1), nil).Once()

		client := &client{
			eth1client:  ecMock,
			reconnectCh: make(chan struct{}, 1),
		}

		isAlive := client.checkClientIsAlive(context.Background())
		require.True(t, isAlive, "Client should be alive when BlockNumber succeeds")
	})

	t.Run("client is not alive", func(t *testing.T) {
		ecMock.On("BlockNumber", mock.Anything).Return(uint64(0), errors.New("no luck")).Once()

		client := &client{
			eth1client:  ecMock,
			reconnectCh: make(chan struct{}, 1),
		}

		isAlive := client.checkClientIsAlive(context.Background())
		require.False(t, isAlive, "Client should not be alive when BlockNumber fails")
	})
}

func TestMagicValue(t *testing.T) {
	// Test that the magic value constant is correct
	expectedMagicValue := [4]byte{0x16, 0x26, 0xba, 0x7e}
	require.Equal(t, expectedMagicValue, erc1271MagicValue, "Magic value should match ERC-1271 specification")
}

func TestERC1271Implementation(t *testing.T) {
	var (
		testContract = "0x123"
		testHash     = [32]byte{0x1, 0x2, 0x3}
		testSig      = []byte{0x4, 0x5, 0x6}
	)

	ecMock := mocks.NewEthClient(t)
	ecMock.On("Close").Return().Once()

	mockErc1271 := mocks.NewErc1271(t)
	mockErc1271.On("IsValidSignature", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			opts := args.Get(0).(*bind.CallOpts)
			hash := args.Get(1).([32]byte)
			sig := args.Get(2).([]byte)

			require.Nil(t, opts, "Opts should be nil")
			require.Equal(t, testHash, hash, "Hash should be passed correctly")
			require.Equal(t, testSig, sig, "Signature should be passed correctly")
		}).
		Return(erc1271MagicValue, nil).Maybe() // can be called multiple times due to polling

	client := NewEthClientRunner(
		"",
		func(ctx context.Context, rawurl string) (EthClient, error) {
			return ecMock, nil
		},
		func(contractAddress string, eth1Client EthClient) (Erc1271, error) {
			require.Equal(t, testContract, contractAddress, "Contract address should be passed to factory")
			require.Equal(t, ecMock, eth1Client, "Eth1Client should be passed to factory")

			return mockErc1271, nil
		},
	)

	// Start the client
	ctx, cancel := context.WithCancel(t.Context())
	doneCh := make(chan struct{})

	go func() {
		client.Run(ctx)
		close(doneCh)
	}()

	// Wait for client to be connected by polling until it's ready
	require.Eventually(t, func() bool {
		valid, err := client.VerifySmartContractBasedSignature(testContract, testHash, testSig)
		return valid && err == nil
	}, 1*time.Second, 10*time.Millisecond, "Client should eventually be connected")

	require.NotEmpty(t, mockErc1271.Calls)

	cancel()

	select {
	case <-doneCh:
	case <-time.After(1 * time.Second):
		require.Fail(t, "Client did not shut down in time")
	}
}

func TestNoopClientCreation(t *testing.T) {
	client := NewDefaultEthClientRunner("")

	require.NotNil(t, client, "Client should be created")
	require.IsType(t, noopClient{}, client, "Client should be a noopClient")
}
