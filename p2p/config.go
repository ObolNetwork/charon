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
	// UDPAddrs defines the lib-p2p udp listen addresses.
	UDPAddrs []string
	// DisableReuseport disables port reuse for libp2p.
	DisableReuseport bool
}

// ParseTCPAddrs returns the configured tcp addresses as typed net tcp addresses.
func (c Config) ParseTCPAddrs() ([]*net.TCPAddr, error) {
	res := make([]*net.TCPAddr, 0, len(c.TCPAddrs))

	for _, addr := range c.TCPAddrs {
		tcpAddr, err := resolveListenTCPAddr(addr)
		if err != nil {
			return nil, err
		}

		res = append(res, tcpAddr)
	}

	return res, nil
}

// ParseUDPAddrs returns the configured udp addresses as typed net udp addresses.
func (c Config) ParseUDPAddrs() ([]*net.UDPAddr, error) {
	res := make([]*net.UDPAddr, 0, len(c.UDPAddrs))

	for _, addr := range c.UDPAddrs {
		udpAddr, err := resolveListenUDPAddr(addr)
		if err != nil {
			return nil, err
		}

		res = append(res, udpAddr)
	}

	return res, nil
}

// UDPMultiaddrs returns the udp configured addresses as libp2p multiaddrs.
func (c Config) UDPMultiaddrs() ([]ma.Multiaddr, error) {
	udpAddrs, err := c.ParseUDPAddrs()
	if err != nil {
		return nil, err
	}

	res := make([]ma.Multiaddr, 0, len(udpAddrs))

	for _, addr := range udpAddrs {
		maddr, err := multiAddrFromIPUDPPort(addr.IP, addr.Port)
		if err != nil {
			return nil, err
		}

		res = append(res, maddr)
	}

	return res, nil
}

// TCPMultiaddrs returns the tcp configured addresses as libp2p multiaddrs.
func (c Config) TCPMultiaddrs() ([]ma.Multiaddr, error) {
	tcpAddrs, err := c.ParseTCPAddrs()
	if err != nil {
		return nil, err
	}

	res := make([]ma.Multiaddr, 0, len(tcpAddrs))

	for _, addr := range tcpAddrs {
		maddr, err := multiAddrFromIPTCPPort(addr.IP, addr.Port)
		if err != nil {
			return nil, err
		}

		res = append(res, maddr)
	}

	return res, nil
}

func resolveListenTCPAddr(addr string) (*net.TCPAddr, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, errors.Wrap(err, "resolve P2P TCP bind addr")
	}

	if tcpAddr.IP == nil {
		return nil, errors.New("p2p bind TCP IP not specified")
	}

	return tcpAddr, nil
}

func resolveListenUDPAddr(addr string) (*net.UDPAddr, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, errors.Wrap(err, "resolve P2P UDP bind addr")
	}

	if udpAddr.IP == nil {
		return nil, errors.New("p2p bind UDP IP not specified")
	}

	return udpAddr, nil
}

// multiAddrFromIPUDPPort returns a multiaddr composed of the provided ip (v4 or v6) and udp port.
func multiAddrFromIPUDPPort(ip net.IP, port int) (ma.Multiaddr, error) {
	if ip.To4() == nil && ip.To16() == nil {
		return nil, errors.New("invalid UDP ip address")
	}

	var typ string
	if ip.To4() != nil {
		typ = "ip4"
	} else if ip.To16() != nil {
		typ = "ip6"
	}

	maddr, err := ma.NewMultiaddr(fmt.Sprintf("/%s/%s/udp/%d/quic-v1", typ, ip.String(), port))
	if err != nil {
		return nil, errors.Wrap(err, "invalid quic-v1 multiaddr")
	}

	return maddr, nil
}

// multiAddrFromIPTCPPort returns a multiaddr composed of the provided ip (v4 or v6) and tcp port.
func multiAddrFromIPTCPPort(ip net.IP, port int) (ma.Multiaddr, error) {
	if ip.To4() == nil && ip.To16() == nil {
		return nil, errors.New("invalid TCP ip address")
	}

	var typ string
	if ip.To4() != nil {
		typ = "ip4"
	} else if ip.To16() != nil {
		typ = "ip6"
	}

	maddr, err := ma.NewMultiaddr(fmt.Sprintf("/%s/%s/tcp/%d", typ, ip.String(), port))
	if err != nil {
		return nil, errors.Wrap(err, "invalid tcp multiaddr")
	}

	return maddr, nil
}
