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
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/netutil"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/expbackoff"
	"github.com/obolnetwork/charon/app/lifecycle"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// MutableUDPNode wraps a discv5 udp node providing support to recreate it if bootnodes change.
type MutableUDPNode struct {
	mu          sync.Mutex
	udpNode     *discover.UDPv5
	prevNames   []string
	refreshFunc func(bootnodes []*enode.Node) (*discover.UDPv5, error)
}

func (n *MutableUDPNode) Set(node *discover.UDPv5) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.udpNode = node
}

// maybeRefresh recreates the udp node if different mutable bootnodes are present.
func (n *MutableUDPNode) maybeRefresh(mutables []*MutablePeer) error {
	var (
		bootnodes []*enode.Node
		names     []string
	)
	for _, mutable := range mutables {
		p, ok := mutable.Peer()
		if !ok {
			continue
		}
		bootnodes = append(bootnodes, &p.Enode)
		names = append(names, p.Name)
	}
	if len(bootnodes) == 0 {
		names = []string{"empty"}
	}

	n.mu.Lock()
	unchanged := strings.Join(n.prevNames, ",") == strings.Join(names, ",")
	n.mu.Unlock()

	if unchanged {
		return nil
	}

	udpNode, err := n.refreshFunc(bootnodes)
	if err != nil {
		return err
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.udpNode != nil {
		n.udpNode.Close()
	}

	n.udpNode = udpNode
	n.prevNames = names

	return nil
}

func (n *MutableUDPNode) Close() {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.udpNode == nil {
		return
	}

	n.udpNode.Close()
	n.udpNode = nil
}

func (n *MutableUDPNode) Resolve(node *enode.Node) *enode.Node {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.udpNode == nil {
		return node // Return node if it cannot be found as per udpNode.Resolve.
	}

	return n.udpNode.Resolve(node)
}

func (n *MutableUDPNode) AllNodes() []*enode.Node {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.udpNode == nil {
		return nil
	}

	return n.udpNode.AllNodes()
}

// NewUDPNode starts and returns a discv5 UDP provider.
func NewUDPNode(ctx context.Context, config Config, ln *enode.LocalNode,
	key *ecdsa.PrivateKey, bootnodes []*MutablePeer,
) (*MutableUDPNode, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", config.UDPAddr)
	if err != nil {
		return nil, errors.Wrap(err, "resolve udp address")
	}

	var allowList *netutil.Netlist
	if config.Allowlist != "" {
		allowList, err = netutil.ParseNetlist(config.Allowlist) // Note empty string would result in "none allowed".
		if err != nil {
			return nil, errors.Wrap(err, "parse allow list")
		}
	}

	mutable := &MutableUDPNode{
		refreshFunc: func(bootnodes []*enode.Node) (*discover.UDPv5, error) {
			conn, err := net.ListenUDP("udp", udpAddr)
			if err != nil {
				return nil, errors.Wrap(err, "listen udp")
			}

			udpNode, err := discover.ListenV5(conn, ln, discover.Config{
				PrivateKey:  key,
				NetRestrict: allowList,
				Bootnodes:   bootnodes,
			})
			if err != nil {
				return nil, errors.Wrap(err, "discv5 listen")
			}

			return udpNode, nil
		},
	}

	// Subscribe to any bootnode updates, which recreates the udp node with new bootnodes
	// since there is no way to update them...
	for _, bootnode := range bootnodes {
		bootnode.Subscribe(func(Peer) {
			if err := mutable.maybeRefresh(bootnodes); err != nil {
				log.Error(ctx, "Recreate discv5 udp node", err)
			} else {
				log.Debug(ctx, "Recreated new discv5 udp node")
			}
		})
	}

	// Return a refreshed mutable udp node
	return mutable, mutable.maybeRefresh(bootnodes)
}

// NewLocalEnode returns a local enode and a peer DB or an error.
func NewLocalEnode(config Config, key *ecdsa.PrivateKey) (*enode.LocalNode, *enode.DB, error) {
	// Empty DB Path creates a new in-memory node database without a persistent backend
	db, err := enode.OpenDB("")
	if err != nil {
		return nil, nil, errors.Wrap(err, "open peer db")
	}

	node := enode.NewLocalNode(db, key)

	// Configure enode with ip and port for tcp libp2p
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

	// Configure enode with ip and port for udp discv5
	udpAddr, err := net.ResolveUDPAddr("udp", config.UDPAddr)
	if err != nil {
		return nil, nil, errors.Wrap(err, "resolve udp address")
	}
	node.SetFallbackIP(udpAddr.IP)
	node.SetFallbackUDP(udpAddr.Port)

	// Configure enode with external (advertised) IP
	if config.ExternalIP != "" {
		ip := net.ParseIP(config.ExternalIP)
		if ip.To4() == nil && ip.To16() == nil {
			return nil, nil, errors.New("invalid p2p external ip")
		}

		node.SetFallbackIP(ip)
		node.SetStaticIP(ip)
	}

	// Configure enode with external (advertised) hostname
	if config.ExternalHost != "" {
		ips, err := net.LookupIP(config.ExternalHost)
		if err != nil || len(ips) == 0 {
			return nil, nil, errors.Wrap(err, "resolve IP of p2p external host flag",
				z.Str("p2p_external_hostname", config.ExternalHost))
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

// NewDiscoveryRouter returns a life cycle hook that links discv5 to libp2p by
// continuously polling discv5 for latest peer ENRs and adding then to libp2p peer store.
func NewDiscoveryRouter(tcpNode host.Host, udpNode *MutableUDPNode, peers []Peer) lifecycle.HookFuncCtx {
	return func(ctx context.Context) {
		ctx = log.WithTopic(ctx, "p2p")
		baseDelay := expbackoff.WithBaseDelay(time.Millisecond * 100) // Poll quickly on startup
		maxDelay := expbackoff.WithMaxDelay(routedAddrTTL * 9 / 10)   // Slow down to 90% of ttl
		backoff := expbackoff.New(ctx, baseDelay, maxDelay)
		addrs := make(map[peer.ID]string)

		for ctx.Err() == nil {
			for _, p := range peers {
				if p.ID == tcpNode.ID() {
					// Skip self
					continue
				}

				addr, ok, err := getDiscoveredAddress(udpNode, p)
				if err != nil {
					log.Error(ctx, "Failed discovering peer address", err)
				} else if ok {
					addrStr := NamedAddr(addr)
					if addrs[p.ID] != addrStr {
						log.Info(ctx, "Discovered new peer address",
							z.Str("peer", PeerName(p.ID)),
							z.Str("address", addrStr))
						addrs[p.ID] = addrStr
					}

					tcpNode.Peerstore().AddAddr(p.ID, addr, routedAddrTTL)
				}
			}

			backoff()
		}
	}
}

// getDiscoveredAddress returns the peer's address as discovered by discv5,
// it returns false if the peer isn't discovered.
func getDiscoveredAddress(udpNode *MutableUDPNode, p Peer) (ma.Multiaddr, bool, error) {
	resolved := udpNode.Resolve(&p.Enode)
	if resolved.Seq() == p.Enode.Seq() || resolved.TCP() == 0 {
		return nil, false, nil // Not discovered
	}

	addr, err := multiAddrFromIPPort(resolved.IP(), resolved.TCP())
	if err != nil {
		return nil, false, err
	}

	return addr, true, nil
}
