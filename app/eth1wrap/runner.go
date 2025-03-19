// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth1wrap

import (
	"context"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/obolnetwork/charon/app/errors"
	erc1271 "github.com/obolnetwork/charon/app/eth1wrap/generated"
	"github.com/obolnetwork/charon/app/expbackoff"
)

//go:generate abigen --abi=build/IERC1271.abi --pkg=erc1271 --out=generated/erc1271.go

var (
	ErrEthClientNotConnected = errors.New("eth1 client is not connected")
	erc1271MagicValue        = [4]byte{0x16, 0x26, 0xba, 0x7e}
)

// NewEthClientRunner returns an uninitialized EL client runner.
func NewEthClientRunner(addr string, ethclientFactory EthClientFactoryFn, erc1271Factory Erc1271FactoryFn) EthClientRunner {
	return &client{
		addr:               addr,
		ethclientFactoryFn: ethclientFactory,
		eth1client:         nil,
		erc1271FactoryFn:   erc1271Factory,
		reconnectCh:        make(chan struct{}, 1),
	}
}

// NewDefaultEthClientRunner returns an uninitialized EL client runner with default implementations.
func NewDefaultEthClientRunner(addr string) EthClientRunner {
	return NewEthClientRunner(addr,
		func(ctx context.Context, url string) (EthClient, error) {
			cl, err := ethclient.DialContext(ctx, url)
			if err != nil {
				return nil, errors.Wrap(err, "failed to connect to eth1 client")
			}

			return cl, nil
		},
		func(contractAddress string, cl EthClient) (Erc1271, error) {
			addr := common.HexToAddress(contractAddress)
			erc1271, err := erc1271.NewErc1271(addr, cl)
			if err != nil {
				return nil, errors.Wrap(err, "failed to create binding to ERC1271 contract")
			}

			return erc1271, nil
		},
	)
}

// client wraps a eth1 client with reconnect logic.
type client struct {
	sync.Mutex

	addr               string
	ethclientFactoryFn EthClientFactoryFn
	eth1client         EthClient
	erc1271FactoryFn   Erc1271FactoryFn
	reconnectCh        chan struct{}
}

// Run starts the eth1 client and reconnects if necessary.
func (cl *client) Run(ctx context.Context) {
	defer func() {
		close(cl.reconnectCh)
		cl.eth1client.Close()
	}()

	var (
		needReconnect = true
		backoff       = expbackoff.New(ctx, expbackoff.WithFastConfig())
	)

	for {
		if needReconnect {
			eth1client, err := cl.ethclientFactoryFn(ctx, cl.addr)
			if err != nil {
				backoff()
				continue
			}
			cl.setClient(eth1client)
		}
		select {
		case <-ctx.Done():
			return
		case <-cl.reconnectCh:
		}

		needReconnect = !cl.checkClientIsAlive(ctx)
		if !needReconnect {
			continue
		}
		cl.close()
	}
}

// VerifySmartContractBasedSignature returns true if sig is a valid signature of hash according to ERC-1271.
func (cl *client) VerifySmartContractBasedSignature(contractAddress string, hash [32]byte, sig []byte) (bool, error) {
	cl.Lock()
	defer cl.Unlock()

	if cl.eth1client == nil {
		return false, ErrEthClientNotConnected
	}

	erc1271, err := cl.erc1271FactoryFn(contractAddress, cl.eth1client)
	if err != nil {
		cl.maybeReconnect()
		return false, err
	}
	result, err := erc1271.IsValidSignature(nil, hash, sig)
	if err != nil {
		cl.maybeReconnect()
		return false, err
	}

	return result == erc1271MagicValue, nil
}

func (cl *client) maybeReconnect() {
	cl.reconnectCh <- struct{}{}
}

func (cl *client) checkClientIsAlive(ctx context.Context) bool {
	if cl.eth1client == nil {
		return false
	}

	// Simple lightweight check if RPC is alive
	if _, err := cl.eth1client.BlockNumber(ctx); err != nil {
		return false
	}

	return true
}

func (cl *client) setClient(client EthClient) {
	cl.Lock()
	defer cl.Unlock()

	cl.eth1client = client
}

func (cl *client) close() {
	cl.Lock()
	defer cl.Unlock()

	if cl.eth1client != nil {
		cl.eth1client.Close()
		cl.eth1client = nil
	}
}
