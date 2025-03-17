// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"

	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/obolnetwork/charon/app/errors"
)

type eth1Client struct {
	client *ethclient.Client
}

func (cl *eth1Client) Close() {
	cl.client.Close()
}

func (cl *eth1Client) BlockNumber(ctx context.Context) (uint64, error) {
	n, err := cl.client.BlockNumber(ctx)
	if err != nil {
		return 0, errors.Wrap(err, "failed to get block number")
	}

	return n, nil
}

func (cl *eth1Client) GetClient() *ethclient.Client {
	return cl.client
}
