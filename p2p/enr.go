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
	"bytes"
	"encoding/base64"
	"strings"

	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/obolnetwork/charon/app/errors"
)

// EncodeENR returns an encoded string format of the enr record.
func EncodeENR(record enr.Record) (string, error) {
	var buf bytes.Buffer
	if err := record.EncodeRLP(&buf); err != nil {
		return "", errors.Wrap(err, "encode rlp")
	}

	return "enr:" + base64.URLEncoding.EncodeToString(buf.Bytes()), nil
}

// DecodeENR returns a enr record decoded from the string.
// See reference github.com/ethereum/go-ethereum@v1.10.10/p2p/dnsdisc/tree.go:378.
func DecodeENR(enrStr string) (enr.Record, error) {
	if enrStr == "" {
		return enr.Record{}, errors.New("enr empty")
	}
	ok := strings.HasPrefix(enrStr, "enr:")
	if !ok {
		return enr.Record{}, errors.New("invalid ENR with no prefix (enr:)")
	}

	enrStr = strings.TrimPrefix(enrStr, "enr:")
	enrBytes, err := base64.URLEncoding.DecodeString(enrStr)
	if err != nil {
		return enr.Record{}, errors.Wrap(err, "base64 enr")
	}

	var record enr.Record
	if err := rlp.DecodeBytes(enrBytes, &record); err != nil {
		return enr.Record{}, errors.Wrap(err, "rlp enr")
	}

	return record, nil
}
