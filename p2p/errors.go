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
	"strings"

	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/obolnetwork/charon/app/errors"
)

// hasErrDialBackoff returns true if the error contains swarm.ErrDialBackoff.
func hasErrDialBackoff(err error) bool {
	dErr := new(swarm.DialError)
	if !errors.As(err, &dErr) {
		return false
	}

	for _, trErr := range dErr.DialErrors {
		if errors.Is(trErr.Cause, swarm.ErrDialBackoff) {
			return true
		}
	}

	return false
}

// dialErrMsgs returns a map of dial error messages by named address or false if the error is not a swarm.DialError.
func dialErrMsgs(err error) (map[string]string, bool) {
	dErr := new(swarm.DialError)
	if !errors.As(err, &dErr) {
		return nil, false
	}

	// We do not expect cause to be populated.
	if dErr.Cause != nil {
		return nil, false
	}

	resp := make(map[string]string)
	for _, trErr := range dErr.DialErrors {
		resp[NamedAddr(trErr.Address)] = trErr.Cause.Error()
	}

	return resp, true
}

// NamedAddr returns the multiaddr as a string with peer names instead of peer IDs.
func NamedAddr(addr ma.Multiaddr) string {
	var resp []string

	ma.ForEach(addr, func(c ma.Component) bool {
		if c.Protocol().Code == ma.P_P2P {
			if id, err := peer.Decode(c.Value()); err == nil {
				resp = append(resp, c.Protocol().Name, PeerName(id))
				return true
			}
		}
		if c.Protocol().Name != "" {
			resp = append(resp, c.Protocol().Name)
		}
		if c.Value() != "" {
			resp = append(resp, strings.TrimPrefix(c.Value(), "/"))
		}

		return true
	})

	return "/" + strings.Join(resp, "/")
}
