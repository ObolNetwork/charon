// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/obolnetwork/charon/app/errors"
)

const (
	// We expect that all consensus protocols will have this prefix.
	consensusProtocolPrefix = "/charon/consensus/"

	// If no suitable protocol is found, this protocol ID is returned.
	// We expect the current QBFT v2.0.0 to be the last resort protocol.
	LastRestortProtocolID = protocolID2
)

var (
	ErrNotConsensusProtocol  = errors.New("not a consensus protocol")
	ErrWrongProtocolIDFormat = errors.New("wrong protocol ID format")
)

// parseProtocolID parses the protocol ID string and returns name and version.
func parseProtocolID(id protocol.ID) (string, *version.Version, error) {
	if !strings.HasPrefix(string(id), consensusProtocolPrefix) {
		return "", nil, ErrNotConsensusProtocol
	}

	nameAndVersion := strings.TrimPrefix(string(id), consensusProtocolPrefix)
	parts := strings.Split(nameAndVersion, "/")
	if len(parts) != 2 {
		return "", nil, ErrWrongProtocolIDFormat
	}

	v, err := version.NewVersion(parts[1])
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to parse version")
	}

	return parts[0], v, nil
}

// ListProtocolNames returns a list of unique protocol names from the given list of protocol IDs.
func ListProtocolNames(protocols []protocol.ID) ([]string, error) {
	namesList := make([]string, 0)
	namesSet := make(map[string]struct{})

	for _, p := range protocols {
		n, _, err := parseProtocolID(p)
		if err != nil {
			return nil, err
		}

		if _, ok := namesSet[n]; !ok {
			namesSet[n] = struct{}{}
			namesList = append(namesList, n)
		}
	}

	return namesList, nil
}

// SelectLatestProtocolID selects the latest version of the preferred protocol.
// The list of protocol IDs is the outcome of InfoSync protocol.
// If no suitable protocol is found, the last resort protocol ID is returned.
func SelectLatestProtocolID(name string, protocols []protocol.ID) protocol.ID {
	var selected protocol.ID
	var selectedVersion *version.Version

	for _, p := range protocols {
		n, v, err := parseProtocolID(p)
		if err != nil {
			// Skip non-consensus protocols.
			continue
		}

		if n != name {
			continue
		}

		if selectedVersion == nil || v.GreaterThan(selectedVersion) {
			selected = p
			selectedVersion = v
		}
	}

	if selected == "" {
		return LastRestortProtocolID
	}

	return selected
}
