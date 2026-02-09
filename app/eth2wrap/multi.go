// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"bytes"
	"context"
	"io"
	"net/http"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
)

// NewMultiForT creates a new mutil client for testing.
func NewMultiForT(clients []Client, fallbacks []Client) Client {
	return &multi{
		clients:   clients,
		fallbacks: fallbacks,
		selector:  newBestSelector(bestPeriod),
	}
}

func newMulti(clients []Client, fallbacks []Client) Client {
	return multi{
		clients:   clients,
		fallbacks: fallbacks,
		selector:  newBestSelector(bestPeriod),
	}
}

// multi implements Client by wrapping multiple clients, calling them in parallel
// and returning the first successful response.
// It also adds prometheus metrics and error wrapping.
// It also implements a "best client" selector.
// When any of the Clients specified fails a request, it will re-try it on the specified
// fallback endpoints, if any.
type multi struct {
	clients   []Client
	fallbacks []Client
	selector  *bestSelector
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

// ClientForAddress returns a scoped multi client that only queries the specified address.
// Returns the original multi client if the address is not found or is empty, meaning requests
// will be sent to all configured clients using the multi-client's normal selection strategy
// rather than being scoped to a single node.
func (m multi) ClientForAddress(addr string) Client {
	if addr == "" {
		return m
	}

	// Find client matching the address
	for _, cl := range m.clients {
		if cl.Address() == addr {
			return multi{
				clients:   []Client{cl},
				fallbacks: m.fallbacks,
				selector:  m.selector,
			}
		}
	}

	// Address not found in clients, check fallbacks
	for _, cl := range m.fallbacks {
		if cl.Address() == addr {
			return multi{
				clients:   []Client{cl},
				fallbacks: nil,
				selector:  m.selector,
			}
		}
	}

	// Address not found, return original multi client
	return m
}

func (m multi) Headers() map[string]string {
	if len(m.clients) == 0 {
		return nil
	}

	return m.clients[0].Headers()
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

	defer incRequest(label)

	res0, err := provide(ctx, m.clients, m.fallbacks,
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

	defer incRequest(label)

	res0, err := provide(ctx, m.clients, m.fallbacks,
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

func (m multi) SetDutiesCache(
	proposerDutiesCache func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) (ProposerDutyWithMeta, error),
	attesterDutiesCache func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) (AttesterDutyWithMeta, error),
	syncCommDutiesCache func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) (SyncDutyWithMeta, error),
) {
	for _, cl := range m.clients {
		cl.SetDutiesCache(proposerDutiesCache, attesterDutiesCache, syncCommDutiesCache)
	}
}

func (m multi) ProposerDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) (ProposerDutyWithMeta, error) {
	const label = "proposer_duties_cache"
	// No latency since this is a cached endpoint.

	defer incRequest(label)

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (ProposerDutyWithMeta, error) {
			return args.client.ProposerDutiesCache(ctx, epoch, vidxs)
		},
		nil, nil,
	)
	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

func (m multi) AttesterDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) (AttesterDutyWithMeta, error) {
	const label = "attester_duties_cache"
	// No latency since this is a cached endpoint.

	defer incRequest(label)

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (AttesterDutyWithMeta, error) {
			return args.client.AttesterDutiesCache(ctx, epoch, vidxs)
		},
		nil, nil,
	)
	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

func (m multi) SyncCommDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) (SyncDutyWithMeta, error) {
	const label = "sync_comm_duties_cache"
	// No latency since this is a cached endpoint.

	defer incRequest(label)

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (SyncDutyWithMeta, error) {
			return args.client.SyncCommDutiesCache(ctx, epoch, vidxs)
		},
		nil, nil,
	)
	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

func (m multi) Proxy(ctx context.Context, req *http.Request) (*http.Response, error) {
	// Duplicate the request body so each backend gets an independent reader
	// req.Clone(ctx) does NOT clone the body reader
	var (
		bodyBytes []byte
		hasBody   bool
	)

	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, errors.Wrap(err, "read request body")
		}
		// Close the original body
		_ = req.Body.Close()
		bodyBytes = b
		hasBody = true
		// Replace with reusable reader for safety
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
	}

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (*http.Response, error) {
			cloned := req.Clone(ctx)
			if hasBody {
				cloned.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				cloned.ContentLength = int64(len(bodyBytes))
				cloned.GetBody = func() (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(bodyBytes)), nil
				}
			} else {
				cloned.Body = nil
			}

			res, err := args.client.Proxy(ctx, cloned)

			return res, err
		},
		nil, nil,
	)

	return res0, err
}
