// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"bytes"
	"context"
	"io"
	"net/http"

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

func (m multi) ProxyRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	// Duplicate the request body so each backend gets an independent reader
	// req.Clone(ctx) does NOT clone the body reader
	var bodyBytes []byte
	var hasBody bool
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
			res, err := args.client.ProxyRequest(ctx, cloned)
			return res, err
		},
		nil, nil,
	)

	return res0, err
}
