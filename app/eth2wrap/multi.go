// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/eth2util/eth2exp"
)

// NewMultiForT creates a new mutil client for testing.
func NewMultiForT(clients []Client, client ...*FallbackClient) Client {
	var fb *FallbackClient

	if len(client) > 0 {
		fb = client[0]
	}

	return &multi{
		clients:  clients,
		fallback: fb,
		selector: newBestSelector(bestPeriod),
	}
}

func newMulti(clients []Client, fallback *FallbackClient) Client {
	return multi{
		clients:  clients,
		fallback: fallback,
		selector: newBestSelector(bestPeriod),
	}
}

// multi implements Client by wrapping multiple clients, calling them in parallel
// and returning the first successful response.
// It also adds prometheus metrics and error wrapping.
// It also implements a "best client" selector.
// When any of the Clients specified fails a request, it will re-try it on the specified
// fallback endpoints, if any.
type multi struct {
	clients  []Client
	fallback *FallbackClient
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

	res0, err := provide(ctx, m.clients, m.fallback,
		func(ctx context.Context, args provideArgs) (ActiveValidators, error) {
			return args.client.ActiveValidators(ctx)
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

	res0, err := provide(ctx, m.clients, m.fallback,
		func(ctx context.Context, args provideArgs) (CompleteValidators, error) {
			return args.client.CompleteValidators(ctx)
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
	defer latency(ctx, label, false)()

	res0, err := provide(ctx, m.clients, m.fallback,
		func(ctx context.Context, args provideArgs) (*eth2exp.ProposerConfigResponse, error) {
			res, bnErr := args.client.ProposerConfig(ctx)
			if bnErr != nil {
				for {
					// use a fallback BN if any
					fe, err := args.fallback.pick()
					if err != nil {
						// no fallback endpoint available, return previous error
						return res, bnErr
					}

					defer args.fallback.place()

					res, bnErr = fe.ProposerConfig(ctx)
					if bnErr == nil {
						return res, bnErr
					}
				}
			}

			return res, bnErr
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
	defer latency(ctx, label, false)()

	res0, err := provide(ctx, m.clients, m.fallback,
		func(ctx context.Context, args provideArgs) ([]*eth2exp.BeaconCommitteeSelection, error) {
			res, bnErr := args.client.AggregateBeaconCommitteeSelections(ctx, selections)
			if bnErr != nil {
				for {
					// use a fallback BN if any
					fe, err := args.fallback.pick()
					if err != nil {
						// no fallback endpoint available, return previous error
						return res, bnErr
					}

					defer args.fallback.place()

					res, bnErr = fe.AggregateBeaconCommitteeSelections(ctx, selections)
					if bnErr == nil {
						return res, bnErr
					}
				}
			}

			return res, bnErr
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
	defer latency(ctx, label, false)()

	res, err := provide(ctx, m.clients, m.fallback,
		func(ctx context.Context, args provideArgs) ([]*eth2exp.SyncCommitteeSelection, error) {
			res, bnErr := args.client.AggregateSyncCommitteeSelections(ctx, selections)
			if bnErr != nil {
				for {
					// use a fallback BN if any
					fe, err := args.fallback.pick()
					if err != nil {
						// no fallback endpoint available, return previous error
						return res, bnErr
					}

					defer args.fallback.place()

					res, bnErr = fe.AggregateSyncCommitteeSelections(ctx, selections)
					if bnErr == nil {
						return res, bnErr
					}
				}
			}

			return res, bnErr
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
	defer latency(ctx, label, false)()

	res, err := provide(ctx, m.clients, m.fallback,
		func(ctx context.Context, args provideArgs) ([]*eth2p0.Attestation, error) {
			res, bnErr := args.client.BlockAttestations(ctx, stateID)
			if bnErr != nil {
				for {
					// use a fallback BN if any
					fe, err := args.fallback.pick()
					if err != nil {
						// no fallback endpoint available, return previous error
						return res, bnErr
					}

					defer args.fallback.place()

					res, bnErr = fe.BlockAttestations(ctx, stateID)
					if bnErr == nil {
						return res, bnErr
					}
				}
			}

			return res, bnErr
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
	defer latency(ctx, label, false)()

	res, err := provide(ctx, m.clients, m.fallback,
		func(ctx context.Context, args provideArgs) (int, error) {
			res, bnErr := args.client.NodePeerCount(ctx)
			if bnErr != nil {
				for {
					// use a fallback BN if any
					fe, err := args.fallback.pick()
					if err != nil {
						// no fallback endpoint available, return previous error
						return res, bnErr
					}

					defer args.fallback.place()

					res, bnErr = fe.NodePeerCount(ctx)
					if bnErr == nil {
						return res, bnErr
					}
				}
			}

			return res, bnErr
		},
		nil, m.selector,
	)
	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res, err
}
