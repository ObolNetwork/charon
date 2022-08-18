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

// NewUDPBootnodes returns the discv5 udp bootnodes from the config.
func NewUDPBootnodes(ctx context.Context, config Config, peers []Peer,
	localEnode enode.ID, lockHashHex string,
) ([]*MutablePeer, error) {
	var resp []*MutablePeer
	for _, rawURL := range config.UDPBootnodes {
		if strings.HasPrefix(rawURL, "http") {
			mutable := new(MutablePeer)
			go resolveBootnode(ctx, rawURL, lockHashHex, mutable.Set)
			resp = append(resp, mutable)

			continue
		}

		node, err := enode.Parse(enode.V4ID{}, rawURL)
		if err != nil {
			return nil, errors.Wrap(err, "invalid bootnode address")
		}

		r := node.Record()
		p, err := NewPeer(*r, -1)
		if err != nil {
			return nil, err
		}

		resp = append(resp, NewMutablePeer(p))
	}

	if config.UDPBootLock {
		for _, p := range peers {
			if p.Enode.ID() == localEnode {
				// Do not include ourselves as bootnode.
				continue
			}

			resp = append(resp, NewMutablePeer(p))
		}
	}

	if len(resp) == 0 {
		return nil, nil
	}

	// Wait until at least one bootnode ENR is resolved
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	for ctx.Err() == nil {
		var resolved bool
		for _, node := range resp {
			if _, ok := node.Peer(); ok {
				resolved = true
			}
		}
		if resolved {
			return resp, nil
		}
		time.Sleep(time.Second * 1)
	}

	return nil, errors.Wrap(ctx.Err(), "timeout resolving bootnode ENR")
}

func resolveBootnode(ctx context.Context, rawURL, lockHashHex string, callback func(Peer)) {
	var prevENR string
	for ctx.Err() == nil {
		node, err := queryBootnodeENR(ctx, rawURL, time.Second*5, lockHashHex)
		if err != nil {
			log.Error(ctx, "Failed resolving bootnode ENR from URL", err, z.Str("url", rawURL))
			return
		}

		newENR := node.String()
		if prevENR != newENR {
			prevENR = newENR

			r := node.Record()
			p, err := NewPeer(*r, -1)
			if err != nil {
				log.Error(ctx, "Failed to create bootnode peer", err)
			} else {
				log.Info(ctx, "Resolved new bootnode ENR",
					z.Str("peer", p.Name),
					z.Str("url", rawURL),
					z.Str("enr", newENR),
				)
				callback(p)
			}
		}

		time.Sleep(time.Minute * 2) // Wait 2min before checking again.
	}
}

// queryBootnodeENR returns the bootnode ENR via a http GET query to the url.
//
// This supports resolving bootnode ENR from known http URLs which is handy
// when bootnodes are deployed in docker-compose or kubernetes
//
// It retries until the context is cancelled.
func queryBootnodeENR(ctx context.Context, bootnodeURL string, backoff time.Duration, lockHashHex string) (*enode.Node, error) {
	parsedURL, err := url.Parse(bootnodeURL)
	if err != nil {
		return nil, errors.Wrap(err, "parse bootnode url")
	} else if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, errors.New("invalid bootnode url")
	}

	var client http.Client
	for ctx.Err() == nil {
		req, err := http.NewRequestWithContext(ctx, "GET", bootnodeURL, nil)
		if err != nil {
			return nil, errors.Wrap(err, "new request")
		}
		req.Header.Set("Charon-Cluster", lockHashHex)

		resp, err := client.Do(req)
		if err != nil {
			log.Warn(ctx, "Failure querying bootnode ENR (will try again)", err)
			time.Sleep(backoff)

			continue
		} else if resp.StatusCode/100 != 2 {
			log.Warn(ctx, "Non-200 response querying bootnode ENR (will try again)", nil, z.Int("status_code", resp.StatusCode))
			time.Sleep(backoff)

			continue
		}

		b, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			log.Warn(ctx, "Failure reading bootnode ENR (will try again)", err)
			time.Sleep(backoff)

			continue
		}

		node, err := enode.Parse(enode.V4ID{}, string(b))
		if err != nil {
			log.Warn(ctx, "Failure parsing ENR (will try again)", err, z.Str("enr", string(b)))
			time.Sleep(backoff)

			continue
		}

		return node, nil
	}

	return nil, errors.Wrap(ctx.Err(), "timeout querying bootnode ENR")
}
