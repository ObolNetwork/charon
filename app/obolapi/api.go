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

package obolapi

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
)

// New returns a new Client.
func New(url string) Client {
	return Client{
		baseURL: url,
	}
}

// Client is the REST client for obol-api requests.
type Client struct {
	baseURL string // Base obol-api URL
}

// PublishLock posts the lockfile to obol-api.
func (c Client) PublishLock(ctx context.Context, lock cluster.Lock) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	addr, err := url.JoinPath(c.baseURL, "lock")
	if err != nil {
		return errors.Wrap(err, "invalid address")
	}

	url, err := url.Parse(addr)
	if err != nil {
		return errors.Wrap(err, "invalid endpoint")
	}

	b, err := lock.MarshalJSON()
	if err != nil {
		return errors.Wrap(err, "marshal lock")
	}

	err = httpPost(ctx, url, b)
	if err != nil {
		return err
	}

	return nil
}

func httpPost(ctx context.Context, url *url.URL, b []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), bytes.NewReader(b))
	if err != nil {
		return errors.Wrap(err, "new POST request with ctx")
	}

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
