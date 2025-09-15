// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"

	"github.com/obolnetwork/charon/dkg/pedersen"
	"github.com/obolnetwork/charon/tbls"
)

// runPedersen runs the Pedersen DKG protocol using the provided board and configuration.
func runPedersen(ctx context.Context, config *pedersen.Config, board *pedersen.Board, numVals int) (shares []share, err error) {
	pushFunc := func(valPubKey tbls.PublicKey, secretShare tbls.PrivateKey, publicShares map[int]tbls.PublicKey) {
		shares = append(shares, share{
			PubKey:       valPubKey,
			SecretShare:  secretShare,
			PublicShares: publicShares,
		})
	}

	err = pedersen.RunDKG(ctx, config, board, numVals, pushFunc)

	return shares, err
}
