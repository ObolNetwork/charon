// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	stdlog "log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
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
	reqCtx := ctx

	maxValAmt := max(len(opts.PubKeys), len(opts.Indices))

	if maxValAmt > 200 {
		reqTimeout := time.Duration(50*maxValAmt) * time.Millisecond

		var cancel context.CancelFunc

		reqCtx, cancel = context.WithTimeout(reqCtx, reqTimeout)
		defer cancel()
	}

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

func (h *httpAdapter) ProxyRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	targetURL, err := url.ParseRequestURI(h.address)
	if err != nil {
		return nil, errors.Wrap(err, "invalid beacon node address", z.Str("address", h.address))
	}

	log.Debug(ctx, "Proxying request to beacon node", z.Str("url", targetURL.Host))

	return ProxyHTTPRequest(ctx, targetURL, req, h.headers)
}

// ProxyHTTPRequest performs an HTTP proxy request using a reverse proxy and returns the response.
// This is a shared helper to avoid code duplication between httpAdapter and beaconmock.
func ProxyHTTPRequest(ctx context.Context, targetURL *url.URL, req *http.Request, headers map[string]string) (*http.Response, error) {
	rp := httputil.NewSingleHostReverseProxy(targetURL)
	rp.ErrorLog = stdlog.New(io.Discard, "", 0)

	// Apply custom director for auth and headers
	defaultDirector := rp.Director
	rp.Director = func(outReq *http.Request) {
		defaultDirector(outReq)

		// Basic auth if present in target URL
		if targetURL.User != nil {
			password, _ := targetURL.User.Password()
			outReq.SetBasicAuth(targetURL.User.Username(), password)
		}

		// Apply headers (override or add)
		for k, v := range headers {
			outReq.Header.Set(k, v)
		}
	}

	// Capture writer buffers headers/status/body.
	captureWriter := newResponseCapture()

	// Ensure reverse proxy errors don't panic the process when used outside the server pipeline.
	var proxyErr error
	rp.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		proxyErr = err
		if !captureWriter.wroteHeader {
			w.WriteHeader(http.StatusBadGateway)
		}
	}

	var abortedByHandler, abortedUnexpected bool
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					abortedByHandler = true
					log.Warn(ctx, "Reverse proxy panicked with ErrAbortHandler", http.ErrAbortHandler)
				} else {
					abortedUnexpected = true
					log.Warn(ctx, "Reverse proxy panicked with unexpected error", nil, z.Any("rec", rec))
				}
			}
		}()
		rp.ServeHTTP(captureWriter, req)
	}()

	if abortedByHandler {
		return nil, errors.Wrap(http.ErrAbortHandler, "reverse proxy panicked",
			z.Int("status_code", captureWriter.status),
			z.Str("url", targetURL.String()),
			z.Str("body", captureWriter.body.String()),
		)
	} else if abortedUnexpected {
		return nil, errors.New("reverse proxy panicked with unexpected error",
			z.Int("status_code", captureWriter.status),
			z.Str("url", targetURL.String()),
			z.Str("body", captureWriter.body.String()),
		)
	} else if proxyErr != nil {
		return nil, errors.Wrap(proxyErr, "proxy error",
			z.Int("status_code", captureWriter.status),
			z.Str("url", targetURL.String()),
			z.Str("body", captureWriter.body.String()),
		)
	}

	// Synthesize an *http.Response from the captured result for the router to mirror
	bodyBytes := captureWriter.body.Bytes()
	res := &http.Response{
		StatusCode:    captureWriter.status,
		Status:        http.StatusText(captureWriter.status),
		Header:        captureWriter.header.Clone(),
		Body:          io.NopCloser(bytes.NewReader(bodyBytes)),
		ContentLength: int64(len(bodyBytes)),
		Request:       req,
	}

	return res, nil
}

// responseCapture is a buffered ResponseWriter that records headers, status and body.
type responseCapture struct {
	header      http.Header
	body        bytes.Buffer
	status      int
	wroteHeader bool
}

func newResponseCapture() *responseCapture {
	return &responseCapture{header: make(http.Header), status: http.StatusOK}
}

func (c *responseCapture) Header() http.Header { return c.header }

func (c *responseCapture) WriteHeader(code int) {
	if c.wroteHeader {
		return
	}
	c.wroteHeader = true
	c.status = code
}

func (c *responseCapture) Write(p []byte) (int, error) {
	if !c.wroteHeader {
		c.WriteHeader(http.StatusOK)
	}
	n, err := c.body.Write(p)
	if err != nil {
		return n, errors.Wrap(err, "write to capture buffer")
	}
	return n, nil
}

// Flush implements http.Flusher for compatibility with ReverseProxy flush calls
// No need for Flush implementation since we buffer the entire response to memory
func (*responseCapture) Flush() {}
