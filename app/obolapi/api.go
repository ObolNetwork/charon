// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

	// defaultTimeout is the default HTTP request timeout if not specified
	defaultTimeout = 10 * time.Second
)

// New returns a new Client.
func New(urlStr string, options ...func(*Client)) (Client, error) {
	_, err := url.ParseRequestURI(urlStr) // check that urlStr is valid
	if err != nil {
		return Client{}, errors.Wrap(err, "could not parse Obol API URL")
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
		panic(errors.Wrap(err, "could not parse Obol API URL, this should never happen"))
	}

	return baseURL
}

// PublishLock posts the lockfile to obol-api.
// It respects the timeout specified in the Client instance.
func (c Client) PublishLock(ctx context.Context, lock cluster.Lock) error {
	addr := c.url()
	addr.Path = "lock"

	b, err := lock.MarshalJSON()
	if err != nil {
		return errors.Wrap(err, "marshal lock")
	}

	ctx, cancel := context.WithTimeout(ctx, c.reqTimeout)
	defer cancel()

	err = httpPost(ctx, addr, b)
	if err != nil {
		return err
	}

	return nil
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

func httpPost(ctx context.Context, url *url.URL, b []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), bytes.NewReader(b))
	if err != nil {
		return errors.Wrap(err, "new POST request with ctx")
	}
	req.Header.Add("Content-Type", "application/json")

	res, err := new(http.Client).Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to call POST endpoint")
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "failed to read POST response")
	}

	if res.StatusCode/100 != 2 {
		return errors.New("post failed", z.Int("status", res.StatusCode), z.Str("body", string(data)))
	}

	return nil
}
