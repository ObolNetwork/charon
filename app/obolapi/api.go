// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
)

const (
	// launchpadReturnPath is the URL path at which one can find details for a given cluster lock hash.
	launchpadReturnPath = "/clusters/details"

	// lockQueryStr is the URL query string for the lock hash parameter.
	lockQueryStr = "lockHash"
)

// New returns a new Client.
func New(urlStr string) (Client, error) {
	apiURL, err := url.ParseRequestURI(urlStr)
	if err != nil {
		return Client{}, errors.Wrap(err, "could not parse Obol API URL")
	}

	return Client{
		baseURL: apiURL,
	}, nil
}

// Client is the REST client for obol-api requests.
type Client struct {
	baseURL *url.URL // Base obol-api URL
}

// PublishLock posts the lockfile to obol-api.
func (c Client) PublishLock(ctx context.Context, lock cluster.Lock) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	addr := *c.baseURL
	addr.Path = "lock"

	b, err := lock.MarshalJSON()
	if err != nil {
		return errors.Wrap(err, "marshal lock")
	}

	err = httpPost(ctx, &addr, b)
	if err != nil {
		return err
	}

	return nil
}

// LaunchpadURLForLock returns the Launchpad cluster dashboard page for a given lock, on the given
// Obol API client.
func (c Client) LaunchpadURLForLock(lock cluster.Lock) string {
	lURL := *c.baseURL

	lURL.Path = launchpadReturnPath

	qs := url.Values{}

	qs.Set(lockQueryStr, hex.EncodeToString(lock.LockHash))

	lURL.RawQuery = qs.Encode()

	return lURL.String()
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
