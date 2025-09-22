// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"

	"github.com/obolnetwork/charon/dkg/pedersen"
)

type AddOperatorsConfig struct {
	OutputDir    string
	NewENRs      []string
	NewThreshold int
}

type RemoveOperatorsConfig struct {
	OutputDir    string
	OldENRs      []string
	NewThreshold int
}

func RunReshareProtocol(ctx context.Context, outputDir string, dkgConfig Config) error {
	return RunProtocol(ctx, newReshareProtocol(outputDir), dkgConfig)
}

func RunAddOperatorsProtocol(ctx context.Context, config AddOperatorsConfig, dkgConfig Config) error {
	return RunProtocol(ctx, newAddOperatorsProtocol(config), dkgConfig)
}

func RunRemoveOperatorsProtocol(ctx context.Context, config RemoveOperatorsConfig, dkgConfig Config) error {
	return RunProtocol(ctx, newRemoveOperatorsProtocol(config), dkgConfig)
}

// runPedersenDKG runs the Pedersen DKG protocol using the provided board and configuration.
func runPedersenDKG(ctx context.Context, config *pedersen.Config, board *pedersen.Board, numVals int) ([]share, error) {
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
