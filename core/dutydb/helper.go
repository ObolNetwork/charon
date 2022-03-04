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

package dutydb

import (
	"encoding/hex"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

// getAggBitsHex returns the aggregation bits hex for a committee
// with length validators and the validator as index set to true.
func getAggBitsHex(length, index uint64) (string, error) {
	if length == 0 {
		return "0x00", nil
	}

	if length <= index {
		return "", errors.New("agg bit index not smaller than length",
			z.U64("length", length), z.U64("index", index))
	}

	extra := uint64(1)
	if length%8 == 0 {
		extra = 0
	}

	buckets := length/8 + extra
	bitList := make([]byte, buckets)

	offset := buckets - 1 - index/8
	bitList[offset] = byte(0x01 << (index % 8))

	return "0x" + hex.EncodeToString(bitList), nil
}
