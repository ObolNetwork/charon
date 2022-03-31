// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package p2p

import (
	"context"
	"crypto/ecdsa"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/netutil"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// NewUDPNode starts and returns a discv5 UDP implementation.
//nolint:revive
func NewUDPNode(ctx context.Context, config Config, ln *enode.LocalNode, key *ecdsa.PrivateKey,
	enrs []enr.Record,
) (*discover.UDPv5, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", config.UDPAddr)
	if err != nil {
		return nil, errors.Wrap(err, "resolve udp address")
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, errors.Wrap(err, "parse udp address")
	}

	netlist, err := netutil.ParseNetlist(config.Allowlist)
	if err != nil {
		return nil, errors.Wrap(err, "parse allow list")
	}

	var bootnodes []*enode.Node

	for _, bootnode := range config.UDPBootnodes {
		if strings.HasPrefix(bootnode, "http") {
			// Query bootnode ENR via http, retry for 1min with 5sec backoff.
			inner, cancel := context.WithTimeout(ctx, time.Minute)
			bootnode, err = queryBootnodeENR(inner, bootnode, time.Second*5)
			cancel()
			if err != nil {
				return nil, err
			}
		}

		node, err := enode.Parse(enode.V4ID{}, bootnode)
		if err != nil {
			return nil, errors.Wrap(err, "invalid bootnode url")
		}

		bootnodes = append(bootnodes, node)
	}

	if config.UDPBootManifest {
		for _, record := range enrs {
			record := record
			node, err := enode.New(enode.V4ID{}, &record)
			if err != nil {
				return nil, errors.Wrap(err, "new enode")
			}

			if ln.ID() == node.ID() {
				// Do not add local node as bootnode
				continue
			}

			bootnodes = append(bootnodes, node)
		}
	}

	node, err := discover.ListenV5(conn, ln, discover.Config{
		PrivateKey:  key,
		NetRestrict: netlist,
		Bootnodes:   bootnodes,
	})
	if err != nil {
		return nil, errors.Wrap(err, "discv5 listen")
	}

	return node, nil
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
			log.Warn(ctx, "Failure querying bootnode ENR, trying again in 5s...", z.Err(err))
			time.Sleep(backoff)

			continue
		} else if resp.StatusCode/100 != 2 {
			return "", errors.Wrap(err, "non-200 response querying bootnode ENR")
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

// NewLocalEnode returns a local enode and a peer DB or an error.
func NewLocalEnode(config Config, key *ecdsa.PrivateKey) (*enode.LocalNode, *enode.DB, error) {
	db, err := enode.OpenDB(config.DBPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "open peer db")
	}

	udpAddr, err := net.ResolveUDPAddr("udp", config.UDPAddr)
	if err != nil {
		return nil, nil, errors.Wrap(err, "resolve udp address")
	}

	tcpAddrs, err := config.ParseTCPAddrs()
	if err != nil {
		return nil, nil, err
	}

	node := enode.NewLocalNode(db, key)

	for _, addr := range tcpAddrs {
		if v4 := addr.IP.To4(); v4 != nil {
			node.Set(enr.IPv4(v4))
		} else if v6 := addr.IP.To16(); v6 != nil {
			node.Set(enr.IPv6(v6))
		}
		node.Set(enr.TCP(addr.Port))
	}

	node.SetFallbackIP(udpAddr.IP)
	node.SetFallbackUDP(udpAddr.Port)

	return node, db, nil
}
