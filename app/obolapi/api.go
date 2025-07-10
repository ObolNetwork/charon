// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
)

const (
	// launchpadReturnPathFmt is the URL path format string at which one can find details for a given cluster lock hash.
	launchpadReturnPathFmt = "/lock/0x%X/launchpad"

	// defaultTimeout is the default HTTP request timeout if not specified.
	defaultTimeout = 10 * time.Second
)

// New returns a new Client.
func New(urlStr string, options ...func(*Client)) (Client, error) {
	_, err := url.ParseRequestURI(urlStr) // check that urlStr is valid
	if err != nil {
		return Client{}, errors.Wrap(err, "parse Obol API URL")
	}

	// always set a default timeout, even if no options are provided
	options = append([]func(*Client){WithTimeout(defaultTimeout)}, options...)
	cl := Client{
		baseURL: urlStr,
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
}

// WithTimeout sets the HTTP request timeout for all Client calls to the provided value.
func WithTimeout(timeout time.Duration) func(*Client) {
	return func(client *Client) {
		client.reqTimeout = timeout
	}
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

func httpPost(ctx context.Context, url *url.URL, body []byte, headers map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), bytes.NewReader(body))
	if err != nil {
		return errors.Wrap(err, "new POST request with ctx")
	}

	req.Header.Add("Content-Type", "application/json")

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

		return errors.New("http POST failed", z.Int("status", res.StatusCode), z.Str("body", string(data)))
	}

	return nil
}

func httpGet(ctx context.Context, url *url.URL, headers map[string]string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "new GET request with ctx")
	}

	for key, val := range headers {
		req.Header.Set(key, val)
	}

	res, err := new(http.Client).Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "call GET endpoint")
	}

	if res.StatusCode/100 != 2 {
		if res.StatusCode == http.StatusNotFound {
			return nil, ErrNoExit
		}

		data, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, errors.Wrap(err, "read POST response", z.Int("status", res.StatusCode))
		}

		return nil, errors.New("http GET failed", z.Int("status", res.StatusCode), z.Str("body", string(data)))
	}

	return res.Body, nil
}

func httpDelete(ctx context.Context, url *url.URL, headers map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url.String(), nil)
	if err != nil {
		return errors.Wrap(err, "new DELETE request with ctx")
	}

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
			return ErrNoExit
		}

		return errors.New("http DELETE failed", z.Int("status", res.StatusCode))
	}

	return nil
}
