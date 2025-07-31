// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/eth2util"
)

// NewHTTPAdapterForT returns a http adapter for testing non-eth2service methods as it is nil.
func NewHTTPAdapterForT(_ *testing.T, address string, headers map[string]string, timeout time.Duration) Client {
	return newHTTPAdapter(nil, address, headers, timeout)
}

// AdaptEth2HTTP returns a Client wrapping an eth2http service by adding experimental endpoints.
// Note that the returned client doesn't wrap errors, so they are unstructured without stacktraces.
func AdaptEth2HTTP(eth2Svc *eth2http.Service, headers map[string]string, timeout time.Duration) Client {
	return newHTTPAdapter(eth2Svc, eth2Svc.Address(), headers, timeout)
}

// newHTTPAdapter returns a new http adapter.
func newHTTPAdapter(ethSvc *eth2http.Service, address string, headers map[string]string, timeout time.Duration) *httpAdapter {
	return &httpAdapter{
		Service: ethSvc,
		address: address,
		headers: headers,
		timeout: timeout,
	}
}

// httpAdapter implements Client by wrapping and adding the following to eth2http.Service:
//   - interfaces not present in go-eth2-client
//   - experimental interfaces
type httpAdapter struct {
	*eth2http.Service

	address     string
	headers     map[string]string
	timeout     time.Duration
	valCacheMu  sync.RWMutex
	valCache    func(context.Context) (ActiveValidators, CompleteValidators, error)
	forkVersion [4]byte
}

func (h *httpAdapter) SetForkVersion(forkVersion [4]byte) {
	h.forkVersion = forkVersion
}

func (h *httpAdapter) SetValidatorCache(valCache func(context.Context) (ActiveValidators, CompleteValidators, error)) {
	h.valCacheMu.Lock()
	h.valCache = valCache
	h.valCacheMu.Unlock()
}

func (h *httpAdapter) ActiveValidators(ctx context.Context) (ActiveValidators, error) {
	h.valCacheMu.RLock()
	defer h.valCacheMu.RUnlock()

	if h.valCache == nil {
		return nil, errors.New("no active validator cache")
	}

	active, _, err := h.valCache(ctx)

	return active, err
}

func (h *httpAdapter) CompleteValidators(ctx context.Context) (CompleteValidators, error) {
	h.valCacheMu.RLock()
	defer h.valCacheMu.RUnlock()

	if h.valCache == nil {
		return nil, errors.New("no active validator cache")
	}

	_, complete, err := h.valCache(ctx)

	return complete, err
}

// Validators returns the validators as requested in opts.
// If the amount of validators requested is greater than 200, exponentially increase the timeout: on crowded testnets
// this HTTP call takes a long time.
func (h *httpAdapter) Validators(ctx context.Context, opts *api.ValidatorsOpts) (
	*api.Response[map[eth2p0.ValidatorIndex]*apiv1.Validator],
	error,
) {
	var cancel func()

	reqCtx := ctx

	maxValAmt := max(len(opts.PubKeys), len(opts.Indices))

	if maxValAmt > 200 {
		reqTimeout := time.Duration(50*maxValAmt) * time.Millisecond
		reqCtx, cancel = context.WithTimeout(reqCtx, reqTimeout)
	}

	defer func() {
		if cancel != nil {
			cancel()
		}
	}()

	return h.Service.Validators(reqCtx, opts)
}

// Domain returns the signing domain for a given domain type.
// After EIP-7044, the VOLUNTARY_EXIT domain must always return a domain relative to the Capella hardfork.
// This method returns just that for that domain type, otherwise follows the standard go-eth2-client flow.
func (h *httpAdapter) Domain(ctx context.Context, domainType eth2p0.DomainType, epoch eth2p0.Epoch) (eth2p0.Domain, error) {
	if domainType == (eth2p0.DomainType{0x04, 0x00, 0x00, 0x00}) { // voluntary exit domain
		domain, err := eth2util.CapellaDomain(ctx, "0x"+hex.EncodeToString(h.forkVersion[:]), h.Service, h.Service)
		if err != nil {
			return eth2p0.Domain{}, errors.Wrap(err, "get domain")
		}

		return domain, nil
	}

	return h.Service.Domain(ctx, domainType, epoch)
}
