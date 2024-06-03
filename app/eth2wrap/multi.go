// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/eth2util/eth2exp"
)

// NewMultiForT creates a new mutil client for testing.
func NewMultiForT(clients []Client) Client {
	return &multi{
		clients:  clients,
		selector: newBestSelector(bestPeriod),
	}
}

func newMulti(clients []Client) Client {
	return multi{
		clients:  clients,
		selector: newBestSelector(bestPeriod),
	}
}

// multi implements Client by wrapping multiple clients, calling them in parallel
// and returning the first successful response.
// It also adds prometheus metrics and error wrapping.
// It also implements a best client selector.
type multi struct {
	clients  []Client
	selector *bestSelector
}

func (m multi) SetForkVersion(forkVersion [4]byte) {
	for _, cl := range m.clients {
		cl.SetForkVersion(forkVersion)
	}
}

func (multi) Name() string {
	return "eth2wrap.multi"
}

func (m multi) Address() string {
	address, ok := m.selector.BestAddress()
	if !ok {
		return m.clients[0].Address()
	}

	return address
}

func (m multi) IsActive() bool {
	for _, cl := range m.clients {
		if cl.IsActive() {
			return true
		}
	}

	return false
}

func (m multi) IsSynced() bool {
	for _, cl := range m.clients {
		if cl.IsSynced() {
			return true
		}
	}

	return false
}

func (m multi) SetValidatorCache(valCache func(context.Context) (ActiveValidators, CompleteValidators, error)) {
	for _, cl := range m.clients {
		cl.SetValidatorCache(valCache)
	}
}

func (m multi) ActiveValidators(ctx context.Context) (ActiveValidators, error) {
	const label = "active_validators"
	// No latency since this is a cached endpoint.

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) (ActiveValidators, error) {
			return cl.ActiveValidators(ctx)
		},
		nil, nil,
	)
	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

func (m multi) CompleteValidators(ctx context.Context) (CompleteValidators, error) {
	const label = "complete_validators"
	// No latency since this is a cached endpoint.

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) (CompleteValidators, error) {
			return cl.CompleteValidators(ctx)
		},
		nil, nil,
	)
	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

func (m multi) ProposerConfig(ctx context.Context) (*eth2exp.ProposerConfigResponse, error) {
	const label = "proposer_config"
	defer latency(label)()

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) (*eth2exp.ProposerConfigResponse, error) {
			return cl.ProposerConfig(ctx)
		},
		nil, m.selector,
	)
	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

func (m multi) AggregateBeaconCommitteeSelections(ctx context.Context, selections []*eth2exp.BeaconCommitteeSelection) ([]*eth2exp.BeaconCommitteeSelection, error) {
	const label = "aggregate_beacon_committee_selections"
	defer latency(label)()

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) ([]*eth2exp.BeaconCommitteeSelection, error) {
			return cl.AggregateBeaconCommitteeSelections(ctx, selections)
		},
		nil, m.selector,
	)
	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

func (m multi) AggregateSyncCommitteeSelections(ctx context.Context, selections []*eth2exp.SyncCommitteeSelection) ([]*eth2exp.SyncCommitteeSelection, error) {
	const label = "aggregate_sync_committee_selections"
	defer latency(label)()

	res, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) ([]*eth2exp.SyncCommitteeSelection, error) {
			return cl.AggregateSyncCommitteeSelections(ctx, selections)
		},
		nil, m.selector,
	)
	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res, err
}

func (m multi) BlockAttestations(ctx context.Context, stateID string) ([]*eth2p0.Attestation, error) {
	const label = "block_attestations"
	defer latency(label)()

	res, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) ([]*eth2p0.Attestation, error) {
			return cl.BlockAttestations(ctx, stateID)
		},
		nil, m.selector,
	)
	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res, err
}

func (m multi) NodePeerCount(ctx context.Context) (int, error) {
	const label = "node_peer_count"
	defer latency(label)()

	res, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) (int, error) {
			return cl.NodePeerCount(ctx)
		},
		nil, m.selector,
	)
	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res, err
}
