// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth1wrap

import (
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/obolnetwork/charon/app/errors"
	erc1271 "github.com/obolnetwork/charon/app/eth1wrap/generated"
)

//go:generate abigen --abi=build/IERC1271.abi --pkg=erc1271 --out=generated/erc1271.go

var (
	ERC1271_MAGIC_VALUE = [4]byte{0x16, 0x26, 0xba, 0x7e}
)

// NewEth1Client returns a initiliazed eth1 JSON-RPC client.
func NewEth1Client(addr string) (*Client, error) {
	cl := NewLazyEth1Client(addr)
	err := cl.initializeClient()

	return cl, err
}

// NewEth1Client returns an uninitialized eth1 JSON-RPC client.
func NewLazyEth1Client(addr string) *Client {
	return &Client{
		eth1Cl:                 nil,
		executionEngineAddress: addr,
	}
}

// Client wraps a eth1 client
type Client struct {
	eth1ClMu               sync.RWMutex
	eth1Cl                 *ethclient.Client
	executionEngineAddress string
}

// maybeInitializeClient initializes the eth1 client if not initialized.
func (cl *Client) maybeInitializeClient() error {
	if cl.executionEngineAddress == "" {
		return errors.New("empty execution engine address<")
	}

	// faster than acquiring a write lock
	cl.eth1ClMu.RLock()
	if cl.eth1Cl != nil {
		cl.eth1ClMu.RUnlock()
		return nil
	}
	cl.eth1ClMu.RUnlock()

	// need write lock to initialize
	cl.eth1ClMu.Lock()
	defer cl.eth1ClMu.Unlock()

	// double-check
	if cl.eth1Cl != nil {
		return nil
	}

	if cl.eth1Cl == nil {
		err := cl.initializeClient()
		if err != nil {
			return err
		}
	}

	return nil
}

// initializeClient initializes the eth1 client. This function is not thread safe.
func (cl *Client) initializeClient() error {
	eth1Cl, err := ethclient.Dial(cl.executionEngineAddress)
	if err != nil {
		return errors.Wrap(err, "failed to dial execution engine address")
	}

	cl.eth1Cl = eth1Cl

	return nil
}

// VerifySmartContractBasedSignature returns true if sig is a valid signature of hash according to ERC-1271.
func (cl *Client) VerifySmartContractBasedSignature(contractAddress string, hash [32]byte, sig []byte) (bool, error) {
	err := cl.maybeInitializeClient()
	if err != nil {
		return false, nil
	}

	addr := common.HexToAddress(contractAddress)

	erc1271, err := erc1271.NewErc1271(addr, cl.eth1Cl)
	if err != nil {
		return false, err
	}

	result, err := erc1271.IsValidSignature(nil, hash, sig)
	if err != nil {
		return false, err
	}

	return result == ERC1271_MAGIC_VALUE, nil
}
