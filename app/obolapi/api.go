// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
)

const (
	// launchpadReturnPathFmt is the URL path format string at which one can find details for a given cluster lock hash.
	launchpadReturnPathFmt = "/lock/0x%X/launchpad"

	// defaultTimeout is the default HTTP request timeout if not specified.
	defaultTimeout = 10 * time.Second
)

// ErrLockNotFound is returned when the Obol API responds 404 Not Found to a POST request. For the
// lock hash scoped endpoints (partial exits, deposits and fee recipients) it means the cluster lock
// isn't published to that Obol API, so the data can't be stored until it is.
var ErrLockNotFound = errors.NewSentinel("cluster lock not published to Obol API")

// New returns a new Client.
func New(urlStr string, options ...func(*Client)) (Client, error) {
	_, err := url.ParseRequestURI(urlStr) // check that urlStr is valid
	if err != nil {
		return Client{}, errors.Wrap(err, "parse Obol API URL")
	}

	// always set a default timeout, even if no options are provided
	options = append([]func(*Client){WithTimeout(defaultTimeout)}, options...)
	cl := Client{
		baseURL:   urlStr,
		userAgent: charonUserAgent(),
	}

	for _, opt := range options {
		opt(&cl)
	}

	return cl, nil
}

// Client is the REST client for obol-api requests.
type Client struct {
	baseURL    string        // Base obol-api URL
	reqTimeout time.Duration // Timeout to use for HTTP requests
	userAgent  string        // User-Agent header sent with every request
}

// WithTimeout sets the HTTP request timeout for all Client calls to the provided value.
func WithTimeout(timeout time.Duration) func(*Client) {
	return func(client *Client) {
		client.reqTimeout = timeout
	}
}

// WithUserAgent prefixes the User-Agent header of all Client calls with the provided product,
// e.g. "lido-dv-exit/v0.7.0" sends "lido-dv-exit/v0.7.0 charon/v1.12.0".
func WithUserAgent(product string) func(*Client) {
	return func(client *Client) {
		if product == "" {
			return
		}

		client.userAgent = product + " " + charonUserAgent()
	}
}

// charonUserAgent returns the default User-Agent header value, e.g. "charon/v1.12.0".
func charonUserAgent() string {
	return "charon/" + version.Version.String()
}

// url returns a *url.URL from the baseURL stored in c.
// Will panic if somehow c.baseURL got corrupted, and it's not a valid URL anymore.
func (c Client) url() *url.URL {
	baseURL, err := url.ParseRequestURI(c.baseURL)
	if err != nil {
		panic(errors.Wrap(err, "parse Obol API URL, this should never happen"))
	}

	return baseURL
}

// LaunchpadURLForLock returns the Launchpad cluster dashboard page for a given lock, on the given
// Obol API client.
func (c Client) LaunchpadURLForLock(lock cluster.Lock) string {
	lURL := c.url()

	lURL.Path = launchpadURLPath(lock)

	return lURL.String()
}

func launchpadURLPath(lock cluster.Lock) string {
	return fmt.Sprintf(launchpadReturnPathFmt, lock.LockHash)
}

func (c Client) httpPost(ctx context.Context, url *url.URL, body []byte, headers map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), bytes.NewReader(body))
	if err != nil {
		return errors.Wrap(err, "create POST request")
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	for key, val := range headers {
		req.Header.Set(key, val)
	}

	res, err := new(http.Client).Do(req)
	if err != nil {
		return errors.Wrap(err, "call POST endpoint")
	}
	defer res.Body.Close()

	if res.StatusCode/100 != 2 {
		data, err := io.ReadAll(res.Body)
		if err != nil {
			return errors.Wrap(err, "read POST response", z.Int("status", res.StatusCode))
		}

		if res.StatusCode == http.StatusNotFound {
			return errors.Wrap(ErrLockNotFound, "http POST failed", z.Int("status", res.StatusCode), z.Str("body", string(data)))
		}

		if res.StatusCode != http.StatusConflict {
			return errors.New("http POST failed", z.Int("status", res.StatusCode), z.Str("body", string(data)))
		}

		log.Info(ctx, "Duplicate request ignored by Obol API. Likely another node submitted the same data already.", z.Int("status", res.StatusCode), z.Str("body", string(data)))
	}

	return nil
}

func (c Client) httpGet(ctx context.Context, url *url.URL, headers map[string]string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "create GET request")
	}

	req.Header.Set("User-Agent", c.userAgent)

	for key, val := range headers {
		req.Header.Set(key, val)
	}

	res, err := new(http.Client).Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "call GET endpoint")
	}

	if res.StatusCode/100 != 2 {
		defer res.Body.Close()

		if res.StatusCode == http.StatusNotFound {
			return nil, ErrNoValue
		}

		data, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, errors.Wrap(err, "read GET response", z.Int("status", res.StatusCode))
		}

		return nil, errors.New("http GET failed", z.Int("status", res.StatusCode), z.Str("body", string(data)))
	}

	return res.Body, nil
}

func (c Client) httpDelete(ctx context.Context, url *url.URL, headers map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url.String(), nil)
	if err != nil {
		return errors.Wrap(err, "create DELETE request")
	}

	req.Header.Set("User-Agent", c.userAgent)

	for key, val := range headers {
		req.Header.Set(key, val)
	}

	res, err := new(http.Client).Do(req)
	if err != nil {
		return errors.Wrap(err, "call DELETE endpoint")
	}
	defer res.Body.Close()

	if res.StatusCode/100 != 2 {
		if res.StatusCode == http.StatusNotFound {
			return ErrNoValue
		}

		return errors.New("http DELETE failed", z.Int("status", res.StatusCode))
	}

	return nil
}
