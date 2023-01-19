// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

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

// New returns a new Keymanager.
func New(url string) Keymanager {
	return Keymanager{
		baseURL: url,
	}
}

// Keymanager is the REST client for keymanager API requests.
type Keymanager struct {
	baseURL string // Base keymanager URL
}

// ImportKeystores pushes the keystores to the keymanager API.
// See https://ethereum.github.io/keymanager-APIs/#/Local%20Key%20Manager/importKeystores.
func (km Keymanager) ImportKeystores(ctx context.Context, keystores []keystore.Keystore, passwords []string) error {
	addr, err := url.JoinPath(km.baseURL, "/eth/v1/keystores")
	if err != nil {
		return errors.Wrap(err, "invalid base url", z.Str("base_url", km.baseURL))
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
func (km Keymanager) VerifyConnection(ctx context.Context) error {
	u, err := url.Parse(km.baseURL)
	if err != nil {
		return errors.Wrap(err, "parse address")
	}

	var d net.Dialer
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return errors.Wrap(err, "cannot ping address", z.Str("addr", km.baseURL))
	}
	conn.Close()

	return nil
}

// keymanagerReq represents the keymanager API request body for POST request. Refer: https://ethereum.github.io/keymanager-APIs/#/Local%20Key%20Manager/importKeystores
type keymanagerReq struct {
	Keystores []keystore.Keystore `json:"keystores"`
	Passwords []string            `json:"passwords"`
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
	req.Header.Add("Content-Type", `application/json`)

	resp, err := new(http.Client).Do(req)
	if err != nil {
		return errors.Wrap(err, "post validator keys to keymanager")
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "read response")
	}
	resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return errors.New("failed posting keys", z.Int("status", resp.StatusCode), z.Str("body", string(data)))
	}

	return nil
}
