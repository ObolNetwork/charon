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

// UDPNode wraps a discv5 udp node and adds the bootnodes relays.
type UDPNode struct {
	*discover.UDPv5
	Relays []Peer
}

// NewUDPNode starts and returns a discv5 UDP implementation.
func NewUDPNode(ctx context.Context, config Config, ln *enode.LocalNode, key *ecdsa.PrivateKey,
	peers []Peer,
) (UDPNode, error) {
	// Setup bootnodes and relays
	var (
		bootnodes  []*enode.Node
		bootRelays []Peer
		err        error
	)
	for _, bootnode := range config.UDPBootnodes {
		if strings.HasPrefix(bootnode, "http") {
			// Query bootnode ENR via http, retry for 1min with 5sec backoff.
			inner, cancel := context.WithTimeout(ctx, time.Minute)
			bootnode, err = queryBootnodeENR(inner, bootnode, time.Second*5)
			cancel()
			if err != nil {
				return UDPNode{}, err
			}
		}

		peer, err := newRelayPeer(bootnode)
		if err != nil {
			return UDPNode{}, err
		}

		bootnodes = append(bootnodes, &peer.Enode)

		if config.BootnodeRelay {
			bootRelays = append(bootRelays, peer)
		}
	}

	if config.UDPBootManifest {
		for _, p := range peers {
			if ln.ID() == p.Enode.ID() {
				// Do not add local node as bootnode
				continue
			}
			node := p.Enode // Copy loop variable
			bootnodes = append(bootnodes, &node)
		}
	}

	// Setup discv5 udp listener.
	udpAddr, err := net.ResolveUDPAddr("udp", config.UDPAddr)
	if err != nil {
		return UDPNode{}, errors.Wrap(err, "resolve udp address")
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return UDPNode{}, errors.Wrap(err, "parse udp address")
	}

	netlist, err := netutil.ParseNetlist(config.Allowlist)
	if err != nil {
		return UDPNode{}, errors.Wrap(err, "parse allow list")
	}

	node, err := discover.ListenV5(conn, ln, discover.Config{
		PrivateKey:  key,
		NetRestrict: netlist,
		Bootnodes:   bootnodes,
	})
	if err != nil {
		return UDPNode{}, errors.Wrap(err, "discv5 listen")
	}

	return UDPNode{
		UDPv5:  node,
		Relays: bootRelays,
	}, nil
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

// NewLocalEnode returns a local enode and a peer DB or an error.
func NewLocalEnode(config Config, key *ecdsa.PrivateKey) (*enode.LocalNode, *enode.DB, error) {
	db, err := enode.OpenDB(config.DBPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "open peer db")
	}

	node := enode.NewLocalNode(db, key)

	tcpAddrs, err := config.ParseTCPAddrs()
	if err != nil {
		return nil, nil, err
	}

	for _, addr := range tcpAddrs {
		if v4 := addr.IP.To4(); v4 != nil {
			node.Set(enr.IPv4(v4))
		} else if v6 := addr.IP.To16(); v6 != nil {
			node.Set(enr.IPv6(v6))
		}
		node.Set(enr.TCP(addr.Port))
	}

	udpAddr, err := net.ResolveUDPAddr("udp", config.UDPAddr)
	if err != nil {
		return nil, nil, errors.Wrap(err, "resolve udp address")
	}
	node.SetFallbackIP(udpAddr.IP)
	node.SetFallbackUDP(udpAddr.Port)

	if config.ExternalIP != "" {
		ip := net.ParseIP(config.ExternalIP)
		if ip.To4() == nil && ip.To16() == nil {
			return nil, nil, errors.New("invalid p2p external ip")
		}

		node.SetFallbackIP(ip)
		node.SetStaticIP(ip)
	}

	if config.ExteranlHost != "" {
		ips, err := net.LookupIP(config.ExteranlHost)
		if err != nil || len(ips) == 0 {
			return nil, nil, errors.Wrap(err, "could not resolve p2p external host")
		}

		// Use first IPv4 returned from the resolver.
		// TODO(corver): Figure out how to get ipv6 to work
		for _, ip := range ips {
			if ip.To4() == nil {
				continue
			}
			node.SetFallbackIP(ip)
		}
	}

	return node, db, nil
}
