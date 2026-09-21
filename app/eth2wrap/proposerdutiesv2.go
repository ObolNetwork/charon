// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
)

// ProposerDutiesV2 is the response of the v2 proposer duties endpoint. The duties are
// identical to v1; the dependent root is the E-2 shuffling anchor (the last block of
// two epochs before the requested one) which gloas proposer preferences sign over,
// instead of v1's E-1 anchor.
type ProposerDutiesV2 struct {
	Duties              []*eth2v1.ProposerDuty
	DependentRoot       eth2p0.Root
	ExecutionOptimistic bool
}

// ProposerDutiesV2Provider is the interface for the v2 proposer duties endpoint,
// GET /eth/v2/validator/duties/proposer/{epoch}, not yet present in go-eth2-client.
// TODO(gloas): swap for the eth2client provider and route it through the duties cache
// once attestantio/go-eth2-client#332 merges.
type ProposerDutiesV2Provider interface {
	ProposerDutiesV2(ctx context.Context, epoch eth2p0.Epoch) (ProposerDutiesV2, error)
}
