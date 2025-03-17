// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth1wrap_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth1wrap"
	"github.com/obolnetwork/charon/app/eth1wrap/mocks"
)

const URL = "http://localhost:8545"

func TestNewEth1Client(t *testing.T) {
	client := eth1wrap.NewEth1Client(
		URL,
		func(ctx context.Context, rawurl string) (eth1wrap.Eth1Client, error) {
			return mocks.NewEth1Client(t), nil
		},
		func(contractAddress string, eth1Client eth1wrap.Eth1Client) (eth1wrap.Erc1271, error) {
			return mocks.NewErc1271(t), nil
		},
	)

	require.NotNil(t, client, "NewEth1Client should return a non-nil client")
}

func TestClientRun(t *testing.T) {
	// 1. Create client connection
	// 2. Context is cancelled
	// 3. Connection is closed
	t.Run("connection_successful", func(t *testing.T) {
		mockEth1Client := mocks.NewEth1Client(t)
		mockEth1Client.On("Close").Return().Once()

		client := eth1wrap.NewEth1Client(
			URL,
			func(ctx context.Context, rawurl string) (eth1wrap.Eth1Client, error) {
				return mockEth1Client, nil
			},
			func(contractAddress string, eth1Client eth1wrap.Eth1Client) (eth1wrap.Erc1271, error) {
				return mocks.NewErc1271(t), nil
			},
		)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err := client.Run(ctx)
		require.NoError(t, err)
		mockEth1Client.AssertExpectations(t)
	})

	// 1. Create client connection
	// 2. First attempt to connect fails
	// 3. Retries to connect
	// 4. Second attempt to connect succeeds
	// 5. Context is cancelled
	// 6. Connection is closed
	t.Run("connection_failure", func(t *testing.T) {
		connectionFailed := errors.New("connection failed")
		attemptsCounter := 0

		mockEth1Client := mocks.NewEth1Client(t)
		mockEth1Client.On("Close").Return().Once()

		client := eth1wrap.NewEth1Client(
			URL,
			func(ctx context.Context, rawurl string) (eth1wrap.Eth1Client, error) {
				attemptsCounter++
				if attemptsCounter == 1 {
					return nil, connectionFailed
				}

				return mockEth1Client, nil
			},
			func(contractAddress string, eth1Client eth1wrap.Eth1Client) (eth1wrap.Erc1271, error) {
				return &mocks.Erc1271{}, nil
			},
		)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err := client.Run(ctx)
		require.NoError(t, err)
		require.Greater(t, attemptsCounter, 1, "Should attempt to reconnect after failure")
		mockEth1Client.AssertExpectations(t)
	})

	// 1. Create client connection
	// 2. First call to ERC1271 fails
	// 3. Call checkClientIsAlive (which fails because BlockNumber fails)
	// 4. Reconnects
	// 5. Second call to ERC1271 succeeds
	t.Run("reconnect_when_connection_lost", func(t *testing.T) {
		mockEth1Client := mocks.NewEth1Client(t)
		mockEth1Client.On("BlockNumber", mock.Anything).Return(uint64(0),
			errors.New("connection lost")).Once()
		mockEth1Client.On("Close").Return().Maybe()

		mockErc1271 := mocks.NewErc1271(t)
		mockErc1271.On("IsValidSignature", mock.Anything, mock.Anything, mock.Anything).
			Return([4]byte{}, errors.New("connection lost")).Once()
		mockErc1271.On("IsValidSignature", mock.Anything, mock.Anything, mock.Anything).
			Return([4]byte{0x16, 0x26, 0xba, 0x7e}, nil).Once()

		connectionAttempts := 0

		client := eth1wrap.NewEth1Client(
			URL,
			func(ctx context.Context, rawurl string) (eth1wrap.Eth1Client, error) {
				connectionAttempts++
				return mockEth1Client, nil
			},
			func(contractAddress string, eth1Client eth1wrap.Eth1Client) (eth1wrap.Erc1271, error) {
				return mockErc1271, nil
			},
		)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Run client in a goroutine
		go func() {
			_ = client.Run(ctx)
		}()

		// Give some time for the client to start
		time.Sleep(100 * time.Millisecond)

		// This should fail and trigger maybeReconnect()
		valid, err := client.VerifySmartContractBasedSignature("0x123", [32]byte{}, []byte{})
		require.False(t, valid)
		require.Error(t, err)

		// Give time to reconnect
		time.Sleep(100 * time.Millisecond)

		// Now try again with the success mock
		valid, err = client.VerifySmartContractBasedSignature("0x123", [32]byte{}, []byte{})
		require.True(t, valid)
		require.NoError(t, err)

		require.Greater(t, connectionAttempts, 1, "Should attempt to reconnect after connection lost")
		mockEth1Client.AssertExpectations(t)
		mockErc1271.AssertExpectations(t)
	})
}

func TestVerifySmartContractBasedSignature(t *testing.T) {
	t.Run("client_not_connected", func(t *testing.T) {
		client := eth1wrap.NewEth1Client(
			URL,
			func(ctx context.Context, rawurl string) (eth1wrap.Eth1Client, error) {
				return mocks.NewEth1Client(t), nil
			},
			func(contractAddress string, eth1Client eth1wrap.Eth1Client) (eth1wrap.Erc1271, error) {
				return mocks.NewErc1271(t), nil
			},
		)

		// Without running the client, eth1client should be nil
		valid, err := client.VerifySmartContractBasedSignature("0x123", [32]byte{}, []byte{})
		require.False(t, valid)
		require.ErrorIs(t, err, eth1wrap.ErrEth1ClientNotConnected)
	})

	t.Run("signature_validation_succeeds", func(t *testing.T) {
		mockEth1Client := mocks.NewEth1Client(t)
		mockEth1Client.On("Close").Return().Maybe()

		mockErc1271 := mocks.NewErc1271(t)
		// Return the magic value for a valid signature
		mockErc1271.On("IsValidSignature", mock.Anything, mock.Anything, mock.Anything).
			Return([4]byte{0x16, 0x26, 0xba, 0x7e}, nil).Once()

		client := eth1wrap.NewEth1Client(
			URL,
			func(ctx context.Context, rawurl string) (eth1wrap.Eth1Client, error) {
				return mockEth1Client, nil
			},
			func(contractAddress string, eth1Client eth1wrap.Eth1Client) (eth1wrap.Erc1271, error) {
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

		valid, err := client.VerifySmartContractBasedSignature("0x123", [32]byte{}, []byte{})
		require.NoError(t, err)
		require.True(t, valid)

		mockErc1271.AssertExpectations(t)
		mockEth1Client.AssertExpectations(t)
	})

	t.Run("signature_validation_fails", func(t *testing.T) {
		mockEth1Client := mocks.NewEth1Client(t)
		mockEth1Client.On("Close").Return().Maybe()

		mockErc1271 := new(mocks.Erc1271)
		// Return an invalid magic value
		mockErc1271.On("IsValidSignature", mock.Anything, mock.Anything, mock.Anything).
			Return([4]byte{0x00, 0x00, 0x00, 0x00}, nil).Maybe()

		client := eth1wrap.NewEth1Client(
			URL,
			func(ctx context.Context, rawurl string) (eth1wrap.Eth1Client, error) {
				return mockEth1Client, nil
			},
			func(contractAddress string, eth1Client eth1wrap.Eth1Client) (eth1wrap.Erc1271, error) {
				return mockErc1271, nil
			},
		)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			_ = client.Run(ctx)
		}()

		// Wait for client to initialize
		time.Sleep(100 * time.Millisecond)

		valid, err := client.VerifySmartContractBasedSignature("0x123", [32]byte{}, []byte{})
		require.NoError(t, err)
		require.False(t, valid)
	})
}
