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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/expbackoff"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// NewRelays returns the libp2p relays from the provided addresses.
func NewRelays(ctx context.Context, relayAddrs []string, lockHashHex string,
) ([]*MutablePeer, error) {
	var resp []*MutablePeer
	for _, relayAddr := range relayAddrs {
		if strings.HasPrefix(relayAddr, "http") {
			mutable := new(MutablePeer)
			go resolveRelay(ctx, relayAddr, lockHashHex, mutable.Set)
			resp = append(resp, mutable)

			continue
		}

		addr, err := ma.NewMultiaddr(relayAddr)
		if err != nil {
			return nil, errors.Wrap(err, "invalid relay multiaddr", z.Str("addr", relayAddr))
		}

		info, err := peer.AddrInfoFromP2pAddr(addr)
		if err != nil {
			return nil, errors.Wrap(err, "peer from multiaddr", z.Str("addr", relayAddr))
		}

		resp = append(resp, NewMutablePeer(NewRelayPeer(*info)))
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

// resolveRelay continuously resolves the relay multiaddrs from the HTTP url and returns
// the new Peer when it changes via the callback.
func resolveRelay(ctx context.Context, rawURL, lockHashHex string, callback func(Peer)) {
	var (
		prevAddrs      string
		backoff, reset = expbackoff.NewWithReset(ctx)
	)
	for ctx.Err() == nil {
		addrs, err := queryRelayAddrs(ctx, rawURL, backoff, lockHashHex)
		if err != nil {
			log.Error(ctx, "Failed resolving relay addresses from URL", err, z.Str("url", rawURL))
			return
		}
		reset()

		sort.Slice(addrs, func(i, j int) bool {
			return addrs[i].String() < addrs[j].String()
		})

		newAddrs := fmt.Sprint(addrs)

		if prevAddrs != newAddrs {
			prevAddrs = newAddrs

			infos, err := peer.AddrInfosFromP2pAddrs(addrs...)
			if err != nil {
				log.Error(ctx, "Failed resolving relay ID from addresses", err, z.Any("addrs", addrs))
			} else if len(infos) != 1 {
				log.Error(ctx, "Failed resolving a single relay ID from addresses", nil, z.Int("n", len(infos)))
			} else {
				p := NewRelayPeer(infos[0])
				log.Info(ctx, "Resolved new relay",
					z.Str("peer", p.Name),
					z.Str("url", rawURL),
					z.Any("addrs", p.Addrs),
				)
				callback(p)
			}
		}

		time.Sleep(time.Minute * 2) // Wait 2min before checking again.
	}
}

// queryRelayAddrs returns the relay multiaddrs via a http GET query to the url.
//
// This supports resolving relay addrs from known http URLs which is handy
// when relays are deployed in docker-compose or kubernetes
//
// It retries until the context is cancelled.
func queryRelayAddrs(ctx context.Context, relayURL string, backoff func(), lockHashHex string) ([]ma.Multiaddr, error) {
	parsedURL, err := url.Parse(relayURL)
	if err != nil {
		return nil, errors.Wrap(err, "parse relay url")
	} else if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, errors.New("invalid relay url")
	}

	var (
		client    http.Client
		doBackoff bool
	)
	for ctx.Err() == nil {
		if doBackoff {
			backoff()
		}
		doBackoff = true

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, relayURL, nil)
		if err != nil {
			return nil, errors.Wrap(err, "new request")
		}
		req.Header.Set("Charon-Cluster", lockHashHex)

		resp, err := client.Do(req)
		if err != nil {
			log.Warn(ctx, "Failure querying relay addresses (will try again)", err)
			continue
		} else if resp.StatusCode/100 != 2 {
			log.Warn(ctx, "Non-200 response querying relay addresses (will try again)", nil, z.Int("status_code", resp.StatusCode))
			continue
		}

		b, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			log.Warn(ctx, "Failure reading relay addresses (will try again)", err)
			continue
		}

		if strings.HasPrefix(string(b), "enr:") {
			return nil, errors.New("querying relay address returned ENR instead of multiaddrs")
		}

		var addrs []string
		if err := json.Unmarshal(b, &addrs); err != nil {
			log.Warn(ctx, "Failure parsing relay addresses json (will try again)", err)
			continue
		}

		var maddrs []ma.Multiaddr
		for _, addr := range addrs {
			maddr, err := ma.NewMultiaddr(addr)
			if err != nil {
				log.Warn(ctx, "Failure parsing relay multiaddrs (will try again)", err, z.Str("addr", addr))
				continue
			}
			maddrs = append(maddrs, maddr)
		}

		return maddrs, nil
	}

	return nil, errors.Wrap(ctx.Err(), "timeout querying relay addresses")
}
