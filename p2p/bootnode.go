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

package p2p

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// NewUDPBootnodes returns the udp bootnodes from the config.
func NewUDPBootnodes(ctx context.Context, config Config, peers []Peer,
	localEnode enode.ID,
) ([]*enode.Node, error) {
	var resp []*enode.Node
	for _, rawURL := range config.UDPBootnodes {
		if strings.HasPrefix(rawURL, "http") {
			// Resolve bootnode ENR via http, retry for 1min with 5sec backoff.
			inner, cancel := context.WithTimeout(ctx, time.Minute)
			var err error
			rawURL, err = queryBootnodeENR(inner, rawURL, time.Second*5)
			cancel()
			if err != nil {
				return nil, err
			}
		}

		node, err := enode.Parse(enode.V4ID{}, rawURL)
		if err != nil {
			return nil, errors.Wrap(err, "invalid bootnode address")
		}

		resp = append(resp, node)
	}

	if config.UDPBootLock {
		for _, p := range peers {
			if p.Enode.ID() == localEnode {
				// Do not include ourselves as bootnode.
				continue
			}
			node := p.Enode // Copy loop variable
			resp = append(resp, &node)
		}
	}

	return resp, nil
}

// queryBootnodeENR returns the bootnode ENR via a http GET query to the url.
//
// This supports resolving bootnode ENR from known http URLs which is handy
// when bootnodes are deployed in docker-compose or kubernetes
//
// It retries until the context is cancelled.
func queryBootnodeENR(ctx context.Context, bootnodeURL string, backoff time.Duration) (string, error) {
	parsedURL, err := url.Parse(bootnodeURL)
	if err != nil {
		return "", errors.Wrap(err, "parse bootnode url")
	} else if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "", errors.New("invalid bootnode url")
	}

	var client http.Client
	for ctx.Err() == nil {
		req, err := http.NewRequestWithContext(ctx, "GET", bootnodeURL, nil)
		if err != nil {
			return "", errors.Wrap(err, "new request")
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Warn(ctx, "Failure querying bootnode ENR, trying again in 5s...", err)
			time.Sleep(backoff)

			continue
		} else if resp.StatusCode/100 != 2 {
			return "", errors.New("non-200 response querying bootnode ENR",
				z.Int("status_code", resp.StatusCode))
		}

		b, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return "", errors.Wrap(err, "read response body")
		}

		log.Info(ctx, "Queried bootnode ENR", z.Str("url", bootnodeURL), z.Str("enr", string(b)))

		return string(b), nil
	}

	return "", errors.Wrap(ctx.Err(), "timeout querying bootnode ENR")
}
