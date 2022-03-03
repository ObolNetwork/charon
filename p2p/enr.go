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
