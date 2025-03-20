// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth1wrap_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth1wrap"
	"github.com/obolnetwork/charon/app/eth1wrap/mocks"
)

const URL = "http://localhost:8545"

func TestNewEthClientRunner(t *testing.T) {
	client := eth1wrap.NewEthClientRunner(
		URL,
		func(ctx context.Context, rawurl string) (eth1wrap.EthClient, error) {
			return mocks.NewEthClient(t), nil
		},
		func(contractAddress string, eth1Client eth1wrap.EthClient) (eth1wrap.Erc1271, error) {
			return mocks.NewErc1271(t), nil
		},
	)

	require.NotNil(t, client, "NewEth1Client should return a non-nil client")
}

func TestNewDefaultEthClientRunner(t *testing.T) {
	client := eth1wrap.NewDefaultEthClientRunner(URL)
	require.NotNil(t, client, "NewDefaultEth1Client should return a non-nil client")
}

func TestClientRun(t *testing.T) {
	// 1. Create client connection
	// 2. Context is cancelled
	// 3. Connection is closed
	t.Run("connection successful", func(t *testing.T) {
		mockEth1Client := mocks.NewEthClient(t)
		mockEth1Client.On("Close").Return().Once()

		client := eth1wrap.NewEthClientRunner(
			URL,
			func(ctx context.Context, rawurl string) (eth1wrap.EthClient, error) {
				return mockEth1Client, nil
			},
			func(contractAddress string, eth1Client eth1wrap.EthClient) (eth1wrap.Erc1271, error) {
				return mocks.NewErc1271(t), nil
			},
		)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		client.Run(ctx)
	})

	// 1. Create client connection
	// 2. First attempt to connect fails
	// 3. Retries to connect
	// 4. Second attempt to connect succeeds
	// 5. Context is cancelled
	// 6. Connection is closed
	t.Run("connection failure", func(t *testing.T) {
		connectionFailed := errors.New("connection failed")
		var attemptsCounter atomic.Int32
		doneCh := make(chan struct{})

		mockEth1Client := mocks.NewEthClient(t)
		mockEth1Client.On("Close").Return().Once()

		client := eth1wrap.NewEthClientRunner(
			URL,
			func(ctx context.Context, rawurl string) (eth1wrap.EthClient, error) {
				attemptsCounter.Add(1)
				if attemptsCounter.Load() == 1 {
					return nil, connectionFailed
				}

				return mockEth1Client, nil
			},
			func(contractAddress string, eth1Client eth1wrap.EthClient) (eth1wrap.Erc1271, error) {
				return &mocks.Erc1271{}, nil
			},
		)

		ctx, cancel := context.WithCancel(context.Background())

		go func() {
			client.Run(ctx)
			close(doneCh)
		}()

		require.Eventually(t, func() bool {
			return attemptsCounter.Load() == 2
		}, 1*time.Second, 10*time.Millisecond)

		cancel()
		require.Eventually(t, func() bool {
			<-doneCh
			return true
		}, 1*time.Second, 10*time.Millisecond)
	})

	// 1. Create client connection
	// 2. First call to ERC1271 fails
	// 3. Call checkClientIsAlive (which fails because BlockNumber fails)
	// 4. Reconnects
	// 5. Second call to ERC1271 succeeds
	t.Run("reconnect when connection lost", func(t *testing.T) {
		createFaultyClient := func() eth1wrap.EthClient {
			mockEth1Client := mocks.NewEthClient(t)
			mockEth1Client.On("BlockNumber", mock.Anything).Return(uint64(0),
				errors.New("connection lost")).Once()
			mockEth1Client.On("Close").Return().Once()

			return mockEth1Client
		}

		createGoodClient := func() eth1wrap.EthClient {
			mockEth1Client := mocks.NewEthClient(t)
			mockEth1Client.On("Close").Return().Once()

			return mockEth1Client
		}

		var connectionAttempts atomic.Int32

		client := eth1wrap.NewEthClientRunner(
			URL,
			func(ctx context.Context, rawurl string) (eth1wrap.EthClient, error) {
				connectionAttempts.Add(1)
				if connectionAttempts.Load() == 1 {
					return createFaultyClient(), nil
				}

				return createGoodClient(), nil
			},
			func(contractAddress string, eth1Client eth1wrap.EthClient) (eth1wrap.Erc1271, error) {
				mockErc1271 := mocks.NewErc1271(t)
				if connectionAttempts.Load() == 1 {
					mockErc1271.On("IsValidSignature", mock.Anything, mock.Anything, mock.Anything).
						Return([4]byte{}, errors.New("connection lost")).Once()
				} else {
					mockErc1271.On("IsValidSignature", mock.Anything, mock.Anything, mock.Anything).
						Return([4]byte{0x16, 0x26, 0xba, 0x7e}, nil).Once()
				}

				return mockErc1271, nil
			},
		)

		ctx, cancel := context.WithCancel(context.Background())
		doneCh := make(chan struct{})

		// Run client in a goroutine
		go func() {
			client.Run(ctx)
			close(doneCh)
		}()

		// Wait for the first connection attempt
		require.Eventually(t, func() bool {
			return connectionAttempts.Load() == 1
		}, 1*time.Second, 10*time.Millisecond)

		// This should fail and trigger maybeReconnect()
		valid, err := client.VerifySmartContractBasedSignature("0x123", [32]byte{}, []byte{})
		require.False(t, valid)
		require.Error(t, err)

		// Give time to reconnect
		require.Eventually(t, func() bool {
			return connectionAttempts.Load() == 2
		}, 1*time.Second, 10*time.Millisecond)

		// Now try again with the success mock
		valid, err = client.VerifySmartContractBasedSignature("0x123", [32]byte{}, []byte{})
		require.True(t, valid)
		require.NoError(t, err)

		require.EqualValues(t, connectionAttempts.Load(), 2, "Should attempt to reconnect after connection lost")

		cancel()
		require.Eventually(t, func() bool {
			<-doneCh
			return true
		}, 1*time.Second, 10*time.Millisecond)
	})
}

func TestVerifySmartContractBasedSignature(t *testing.T) {
	t.Run("client not connected", func(t *testing.T) {
		client := eth1wrap.NewEthClientRunner(
			URL,
			func(ctx context.Context, rawurl string) (eth1wrap.EthClient, error) {
				return mocks.NewEthClient(t), nil
			},
			func(contractAddress string, eth1Client eth1wrap.EthClient) (eth1wrap.Erc1271, error) {
				return mocks.NewErc1271(t), nil
			},
		)

		// Without running the client, eth1client should be nil
		valid, err := client.VerifySmartContractBasedSignature("0x123", [32]byte{}, []byte{})
		require.False(t, valid)
		require.ErrorIs(t, err, eth1wrap.ErrEthClientNotConnected)
	})

	t.Run("successful", func(t *testing.T) {
		mockEth1Client := mocks.NewEthClient(t)
		mockEth1Client.On("Close").Return().Maybe()

		mockErc1271 := mocks.NewErc1271(t)
		// Return the magic value for a valid signature
		mockErc1271.On("IsValidSignature", mock.Anything, mock.Anything, mock.Anything).
			Return([4]byte{0x16, 0x26, 0xba, 0x7e}, nil).Once()

		clientCreatedCh := make(chan struct{})
		doneCh := make(chan struct{})

		client := eth1wrap.NewEthClientRunner(
			URL,
			func(ctx context.Context, rawurl string) (eth1wrap.EthClient, error) {
				clientCreatedCh <- struct{}{}
				return mockEth1Client, nil
			},
			func(contractAddress string, eth1Client eth1wrap.EthClient) (eth1wrap.Erc1271, error) {
				return mockErc1271, nil
			},
		)

		// Start the client
		ctx, cancel := context.WithCancel(context.Background())

		go func() {
			client.Run(ctx)
			close(doneCh)
		}()

		// Wait for client to initialize
		<-clientCreatedCh

		valid, err := client.VerifySmartContractBasedSignature("0x123", [32]byte{}, []byte{})
		require.NoError(t, err)
		require.True(t, valid)

		cancel()
		require.Eventually(t, func() bool {
			<-doneCh
			return true
		}, 1*time.Second, 10*time.Millisecond)
	})

	t.Run("signature validation fails", func(t *testing.T) {
		mockEth1Client := mocks.NewEthClient(t)
		mockEth1Client.On("Close").Return().Maybe()

		mockErc1271 := mocks.NewErc1271(t)
		// Return an invalid magic value
		mockErc1271.On("IsValidSignature", mock.Anything, mock.Anything, mock.Anything).
			Return([4]byte{0x00, 0x00, 0x00, 0x00}, nil).Maybe()

		clientCreatedCh := make(chan struct{})
		doneCh := make(chan struct{})

		client := eth1wrap.NewEthClientRunner(
			URL,
			func(ctx context.Context, rawurl string) (eth1wrap.EthClient, error) {
				close(clientCreatedCh)
				return mockEth1Client, nil
			},
			func(contractAddress string, eth1Client eth1wrap.EthClient) (eth1wrap.Erc1271, error) {
				return mockErc1271, nil
			},
		)

		ctx, cancel := context.WithCancel(context.Background())

		go func() {
			client.Run(ctx)
			close(doneCh)
		}()

		// Wait for client to initialize
		<-clientCreatedCh

		valid, err := client.VerifySmartContractBasedSignature("0x123", [32]byte{}, []byte{})
		require.NoError(t, err)
		require.False(t, valid)

		cancel()
		require.Eventually(t, func() bool {
			<-doneCh
			return true
		}, 1*time.Second, 10*time.Millisecond)
	})
}

func TestNoopClient(t *testing.T) {
	t.Run("noop run", func(t *testing.T) {
		client := eth1wrap.NewDefaultEthClientRunner("")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// does nothing and immediately returns
		require.Eventually(t, func() bool {
			client.Run(ctx)
			return true
		}, 1*time.Second, 10*time.Millisecond)
	})

	t.Run("noop verify", func(t *testing.T) {
		client := eth1wrap.NewDefaultEthClientRunner("")

		valid, err := client.VerifySmartContractBasedSignature("0x123", [32]byte{}, []byte{})
		require.False(t, valid)
		require.ErrorIs(t, err, eth1wrap.ErrNoExecutionEngineAddr)
	})
}
