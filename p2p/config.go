// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"fmt"
	"net"

	ma "github.com/multiformats/go-multiaddr"

	"github.com/obolnetwork/charon/app/errors"
)

type Config struct {
	// Relays defines the libp2p relay multiaddrs or URLs.
	Relays []string
	// ExternalIP is the IP advertised by libp2p.
	ExternalIP string
	// ExternalHost is the DNS hostname advertised by libp2p.
	ExternalHost string
	// TCPAddrs defines the lib-p2p tcp listen addresses.
	TCPAddrs []string
	// DisableReuseport disables TCP port reuse for libp2p.
	DisableReuseport bool
}

// ParseTCPAddrs returns the configured tcp addresses as typed net tcp addresses.
func (c Config) ParseTCPAddrs() ([]*net.TCPAddr, error) {
	res := make([]*net.TCPAddr, 0, len(c.TCPAddrs))

	for _, addr := range c.TCPAddrs {
		tcpAddr, err := resolveListenAddr(addr)
		if err != nil {
			return nil, err
		}
		res = append(res, tcpAddr)
	}

	return res, nil
}

// Multiaddrs returns the configured addresses as libp2p multiaddrs.
func (c Config) Multiaddrs() ([]ma.Multiaddr, error) {
	tcpAddrs, err := c.ParseTCPAddrs()
	if err != nil {
		return nil, err
	}

	res := make([]ma.Multiaddr, 0, len(tcpAddrs))

	for _, addr := range tcpAddrs {
		maddr, err := multiAddrFromIPPort(addr.IP, addr.Port)
		if err != nil {
			return nil, err
		}

		res = append(res, maddr)
	}

	return res, nil
}

func resolveListenAddr(addr string) (*net.TCPAddr, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, errors.Wrap(err, "resolve P2P bind addr")
	}

	if tcpAddr.IP == nil {
		return nil, errors.New("p2p bind IP not specified")
	}

	return tcpAddr, nil
}

// multiAddrFromIPPort returns a multiaddr composed of the provided ip (v4 or v6) and tcp port.
func multiAddrFromIPPort(ip net.IP, port int) (ma.Multiaddr, error) {
	if ip.To4() == nil && ip.To16() == nil {
		return nil, errors.New("invalid ip address")
	}

	var typ string
	if ip.To4() != nil {
		typ = "ip4"
	} else if ip.To16() != nil {
		typ = "ip6"
	}

	maddr, err := ma.NewMultiaddr(fmt.Sprintf("/%s/%s/tcp/%d", typ, ip.String(), port))
	if err != nil {
		return nil, errors.Wrap(err, "invalid multiaddr")
	}

	return maddr, nil
}
