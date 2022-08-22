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

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"

	"github.com/obolnetwork/charon/app/errors"
)

// EncodeENR returns an encoded string format of the enr record.
func EncodeENR(record enr.Record) (string, error) {
	n, err := enode.New(enode.V4ID{}, &record)
	if err != nil {
		return "", errors.Wrap(err, "encode ENR")
	}

	return n.String(), nil
}

// DecodeENR returns a enr record decoded from the string.
// See reference github.com/ethereum/go-ethereum@v1.10.10/p2p/dnsdisc/tree.go:378.
func DecodeENR(enrStr string) (enr.Record, error) {
	// Ensure backwards compatibility with older versions with encoded ENR strings.
	enrStr = strings.TrimRight(enrStr, "=")

	node, err := enode.Parse(enode.V4ID{}, enrStr)
	if err != nil {
		return enr.Record{}, errors.Wrap(err, "decode ENR")
	}

	return *node.Record(), nil
}
