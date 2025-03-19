// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth1wrap

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

//go:generate mockery --name EthClient --output=mocks --outpkg=mocks --case=underscore
//go:generate mockery --name Erc1271 --output=mocks --outpkg=mocks --case=underscore
//go:generate mockery --name EthClientRunner --output=mocks --outpkg=mocks --case=underscore

// EthClient defines the interface for the Ethereum EL RPC client.
type EthClient interface {
	Close()
	Client() *rpc.Client
	ChainID(ctx context.Context) (*big.Int, error)
	BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error)
	BlockByNumber(ctx context.Context, number *big.Int) (*types.Block, error)
	BlockNumber(ctx context.Context) (uint64, error)
	PeerCount(ctx context.Context) (uint64, error)
	BlockReceipts(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) ([]*types.Receipt, error)
	HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error)
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
	TransactionByHash(ctx context.Context, hash common.Hash) (*types.Transaction, bool, error)
	TransactionSender(ctx context.Context, tx *types.Transaction, block common.Hash, index uint) (common.Address, error)
	TransactionCount(ctx context.Context, blockHash common.Hash) (uint, error)
	TransactionInBlock(ctx context.Context, blockHash common.Hash, index uint) (*types.Transaction, error)
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	SyncProgress(ctx context.Context) (*ethereum.SyncProgress, error)
	SubscribeNewHead(ctx context.Context, ch chan<- *types.Header) (ethereum.Subscription, error)
	NetworkID(ctx context.Context) (*big.Int, error)
	BalanceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error)
	BalanceAtHash(ctx context.Context, account common.Address, blockHash common.Hash) (*big.Int, error)
	StorageAt(ctx context.Context, account common.Address, key common.Hash, blockNumber *big.Int) ([]byte, error)
	StorageAtHash(ctx context.Context, account common.Address, key common.Hash, blockHash common.Hash) ([]byte, error)
	CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)
	CodeAtHash(ctx context.Context, account common.Address, blockHash common.Hash) ([]byte, error)
	NonceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (uint64, error)
	NonceAtHash(ctx context.Context, account common.Address, blockHash common.Hash) (uint64, error)
	FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error)
	SubscribeFilterLogs(ctx context.Context, q ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error)
	PendingBalanceAt(ctx context.Context, account common.Address) (*big.Int, error)
	PendingStorageAt(ctx context.Context, account common.Address, key common.Hash) ([]byte, error)
	PendingCodeAt(ctx context.Context, account common.Address) ([]byte, error)
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
	PendingTransactionCount(ctx context.Context) (uint, error)
	CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
	CallContractAtHash(ctx context.Context, msg ethereum.CallMsg, blockHash common.Hash) ([]byte, error)
	PendingCallContract(ctx context.Context, msg ethereum.CallMsg) ([]byte, error)
	SuggestGasPrice(ctx context.Context) (*big.Int, error)
	SuggestGasTipCap(ctx context.Context) (*big.Int, error)
	FeeHistory(ctx context.Context, blockCount uint64, lastBlock *big.Int, rewardPercentiles []float64) (*ethereum.FeeHistory, error)
	EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error)
	SendTransaction(ctx context.Context, tx *types.Transaction) error
}

// Ensure that ethclient.Client implements the EthClient interface
var _ EthClient = (*ethclient.Client)(nil)

type EthClientFactoryFn func(ctx context.Context, rawurl string) (EthClient, error)

// EthClientRunner is a JSON-RPC client for eth with reconnect logic.
type EthClientRunner interface {
	Run(ctx context.Context)
	VerifySmartContractBasedSignature(contractAddress string, hash [32]byte, sig []byte) (bool, error)
}

type Erc1271FactoryFn func(contractAddress string, client EthClient) (Erc1271, error)

// Erc1271 is an interface for ERC-1271 smart contracts.
type Erc1271 interface {
	IsValidSignature(opts *bind.CallOpts, hash [32]byte, sig []byte) ([4]byte, error)
}
