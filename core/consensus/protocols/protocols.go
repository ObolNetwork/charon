// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package protocols

import (
	"strings"

	"github.com/libp2p/go-libp2p/core/protocol"
)

const (
	protocolIDPrefix = "/charon/consensus/"

	QBFTv2ProtocolID = "/charon/consensus/qbft/2.0.0"
)

// Protocols returns the supported protocols of this package in order of precedence.
func Protocols() []protocol.ID {
	return []protocol.ID{QBFTv2ProtocolID}
}

// IsSupportedProtocolName returns true if the protocol name is supported.
func IsSupportedProtocolName(name string) bool {
	for _, p := range Protocols() {
		nameAndVersion := strings.TrimPrefix(string(p), protocolIDPrefix)
		parts := strings.Split(nameAndVersion, "/")
		if len(parts) > 0 && parts[0] == strings.ToLower(name) {
			return true
		}
	}

	return false
}
