// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"

	"github.com/obolnetwork/charon/dkg/pedersen"
)

// runPedersen runs the Pedersen DKG protocol using the provided board and configuration.
func runPedersen(ctx context.Context, config *pedersen.Config, board *pedersen.Board, numVals int) ([]share, error) {
	shares, err := pedersen.RunDKG(ctx, config, board, numVals)
	if err != nil {
		return nil, err
	}

	return copyToShares(shares), nil
}

func copyToShares(in []*pedersen.Share) (out []share) {
	out = make([]share, 0, len(in))

	for i := range in {
		out = append(out, share{
			PubKey:       in[i].PubKey,
			SecretShare:  in[i].SecretShare,
			PublicShares: in[i].PublicShares,
		})
	}

	return out
}
