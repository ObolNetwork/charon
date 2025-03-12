// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"bytes"
	"context"
	"encoding/json"
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

	err = httpPost(ctx, addr, b, nil)
	if err != nil {
		return err
	}

	return nil
}

// PublishDefinition posts the cluster definition to obol-api.
// It requires the cluster creator to previously sign Obol's Terms and Conditions.
func (c Client) PublishDefinition(ctx context.Context, def cluster.Definition, sig []byte) error {
	addr := c.url()
	addr.Path = "v1/definition"

	b, err := def.MarshalJSON()
	if err != nil {
		return errors.Wrap(err, "marshal definition")
	}

	headers := map[string]string{
		"authorization": fmt.Sprintf("Bearer 0x%x", sig),
	}

	ctx, cancel := context.WithTimeout(ctx, c.reqTimeout)
	defer cancel()

	return httpPost(ctx, addr, b, headers)
	if err != nil {
		return err
	}

	return nil
}

// VeriftySignedTermsAndConditions verifies if the user address has previously signed Obol's Terms and Conditions.
func (c Client) VerifySignedTermsAndConditions(ctx context.Context, userAddr string) (bool, error) {
	type response struct {
		Signed bool `json:"isTermsAndConditionsSigned"`
	}

	addr := c.url()
	addr.Path = "v1/termsAndConditions/" + userAddr

	ctx, cancel := context.WithTimeout(ctx, c.reqTimeout)
	defer cancel()

	resp, err := httpGet(ctx, addr, nil)
	if err != nil {
		return false, err
	}

	defer resp.Close()

	buf, err := io.ReadAll(resp)
	if err != nil {
		return false, errors.Wrap(err, "read response body")
	}

	var res response
	if err := json.Unmarshal(buf, &res); err != nil {
		return false, errors.Wrap(err, "unmarshal response")
	}

	return res.Signed, nil
}

// SignTermsAndConditions submits the user's signature of Obol's Terms and Conditions to obol-api.
func (c Client) SignTermsAndConditions(ctx context.Context, userAddr string, forkVersion []byte, sig []byte) error {
	type request struct {
		Address                string `json:"address"`
		Version                int    `json:"version"`
		TermsAndConditionsHash string `json:"terms_and_conditions_hash"`
		ForkVersion            string `json:"fork_version"`
	}

	addr := c.url()
	addr.Path = "v1/termsAndConditions"

	req := request{
		Address:                userAddr,
		Version:                1,
		TermsAndConditionsHash: "0xd33721644e8f3afab1495a74abe3523cec12d48b8da6cb760972492ca3f1a273",
		ForkVersion:            fmt.Sprintf("0x%x", forkVersion),
	}

	r, err := json.Marshal(req)
	if err != nil {
		return errors.Wrap(err, "marshal sign terms and Conditions")
	}

	headers := map[string]string{
		"authorization": fmt.Sprintf("Bearer 0x%x", sig),
	}

	ctx, cancel := context.WithTimeout(ctx, c.reqTimeout)
	defer cancel()

	err = httpPost(ctx, addr, r, headers)
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
	req.Header.Add("Content-Type", "application/json")

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
