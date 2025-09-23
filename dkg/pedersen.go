// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
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
