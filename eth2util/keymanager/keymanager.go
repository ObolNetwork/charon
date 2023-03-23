// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package keymanager provides ETH2 keymanager API (https://ethereum.github.io/keymanager-APIs/) functionalities.
package keymanager

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/keystore"
)

// New returns a new Client.
func New(url string) Client {
	return Client{
		baseURL: url,
	}
}

// Client is the REST client for keymanager API requests.
type Client struct {
	baseURL string // Base keymanager URL
}

// ImportKeystores pushes the keystores and passwords to keymanager.
// See https://ethereum.github.io/keymanager-APIs/#/Local%20Key%20Manager/importKeystores.
func (c Client) ImportKeystores(ctx context.Context, keystores []keystore.Keystore, passwords []string) error {
	if len(keystores) != len(passwords) {
		return errors.New("lengths of keystores and passwords don't match",
			z.Int("keystores", len(keystores)), z.Int("passwords", len(passwords)))
	}

	addr, err := url.JoinPath(c.baseURL, "/eth/v1/keystores")
	if err != nil {
		return errors.Wrap(err, "invalid base url", z.Str("base_url", c.baseURL))
	}

	req := keymanagerReq{
		Keystores: keystores,
		Passwords: passwords,
	}

	err = postKeys(ctx, addr, req)
	if err != nil {
		return err
	}

	return nil
}

// VerifyConnection returns an error if the provided keymanager address is not reachable.
func (c Client) VerifyConnection(ctx context.Context) error {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return errors.Wrap(err, "parse address")
	}

	var d net.Dialer
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return errors.Wrap(err, "cannot ping address", z.Str("addr", c.baseURL))
	}
	_ = conn.Close()

	return nil
}

// keymanagerReq represents the keymanager API request body for POST request.
// Refer: https://ethereum.github.io/keymanager-APIs/#/Local%20Key%20Manager/importKeystores
type keymanagerReq struct {
	Keystores []keystore.Keystore `json:"keystores"`
	Passwords []string            `json:"passwords"`
}

// keymanagerJSON is the json formatter for keymanagerReq.
type keymanagerReqJSON struct {
	Keystores []string `json:"keystores"`
	Passwords []string `json:"passwords"`
}

func (k keymanagerReq) MarshalJSON() ([]byte, error) {
	resp := keymanagerReqJSON{
		Passwords: k.Passwords,
	}

	for _, ks := range k.Keystores {
		data, err := json.Marshal(ks)
		if err != nil {
			return nil, errors.Wrap(err, "marshal keystore")
		}

		resp.Keystores = append(resp.Keystores, string(data))
	}

	return json.Marshal(resp)
}

// postKeys pushes the secrets to the provided keymanager address. The HTTP request times out after 10s.
func postKeys(ctx context.Context, addr string, reqBody keymanagerReq) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return errors.New("marshal keymanager request body")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr, bytes.NewReader(reqBytes))
	if err != nil {
		return errors.Wrap(err, "new post request", z.Str("url", addr))
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer api-token-0x0325706d794094cdedb2348a6e81e38923a7021474dba7b319b9b557b8947c313e")

	resp, err := new(http.Client).Do(req)
	if err != nil {
		return errors.Wrap(err, "post validator keys to keymanager")
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "read response")
	}
	_ = resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return errors.New("failed posting keys", z.Int("status", resp.StatusCode), z.Str("body", string(data)))
	}

	return nil
}
