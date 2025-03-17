// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth1wrap

import (
	"context"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/obolnetwork/charon/app/errors"
)

//go:generate abigen --abi=build/IERC1271.abi --pkg=erc1271 --out=generated/erc1271.go
//go:generate mockery --name Eth1Client --output=mocks --outpkg=mocks --case=underscore
//go:generate mockery --name Erc1271 --output=mocks --outpkg=mocks --case=underscore
//go:generate mockery --name Client --output=mocks --outpkg=mocks --case=underscore

var (
	ErrEth1ClientNotConnected = errors.New("eth1 client is not connected")
	erc1271MagicValue         = [4]byte{0x16, 0x26, 0xba, 0x7e}
)

type Eth1ClientFactoryFn func(ctx context.Context, rawurl string) (Eth1Client, error)

// Eth1Client is a JSON-RPC client for eth1.
type Eth1Client interface {
	Close()
	BlockNumber(ctx context.Context) (uint64, error)
	GetClient() *ethclient.Client
}

type Erc1271FactoryFn func(contractAddress string, eth1Client Eth1Client) (Erc1271, error)

// Erc1271 is an interface for ERC-1271 smart contracts.
type Erc1271 interface {
	IsValidSignature(opts *bind.CallOpts, hash [32]byte, sig []byte) ([4]byte, error)
}

// NewEth1Client returns a initiliazed eth1 JSON-RPC client.
func NewEth1Client(addr string, eth1clientFactory Eth1ClientFactoryFn, erc1271Factory Erc1271FactoryFn) *Client {
	return &Client{
		addr:                addr,
		eth1clientFactoryFn: eth1clientFactory,
		eth1client:          nil,
		erc1271FactoryFn:    erc1271Factory,
		reconnectCh:         make(chan struct{}, 1),
	}
}

// Client wraps a eth1 client
type Client struct {
	sync.Mutex

	addr                string
	eth1clientFactoryFn Eth1ClientFactoryFn
	eth1client          Eth1Client
	erc1271FactoryFn    Erc1271FactoryFn
	reconnectCh         chan struct{}
}

// Run starts the eth1 client and reconnects if necessary.
func (cl *Client) Run(ctx context.Context) error {
	defer func() {
		close(cl.reconnectCh)
		cl.closeClient()
	}()

	needReconnect := true

	for {
		if needReconnect {
			eth1client, err := cl.eth1clientFactoryFn(ctx, cl.addr)
			if err != nil {
				// TODO: delay reconnect attempts
				continue
			}
			cl.setClient(eth1client)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-cl.reconnectCh:
		}

		needReconnect = !cl.checkClientIsAlive(ctx)
		if !needReconnect {
			continue
		}
		cl.closeClient()
	}
}

// VerifySmartContractBasedSignature returns true if sig is a valid signature of hash according to ERC-1271.
func (cl *Client) VerifySmartContractBasedSignature(contractAddress string, hash [32]byte, sig []byte) (bool, error) {
	cl.Lock()
	defer cl.Unlock()

	if cl.eth1client == nil {
		return false, ErrEth1ClientNotConnected
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

func (cl *Client) maybeReconnect() {
	cl.reconnectCh <- struct{}{}
}

func (cl *Client) checkClientIsAlive(ctx context.Context) bool {
	if cl.eth1client == nil {
		return false
	}

	// Simple lightweight check if RPC is alive
	if _, err := cl.eth1client.BlockNumber(ctx); err != nil {
		return false
	}

	return true
}

func (cl *Client) setClient(client Eth1Client) {
	cl.Lock()
	defer cl.Unlock()
	cl.eth1client = client
}

func (cl *Client) closeClient() {
	cl.Lock()
	defer cl.Unlock()

	if cl.eth1client != nil {
		cl.eth1client.Close()
		cl.eth1client = nil
	}
}
