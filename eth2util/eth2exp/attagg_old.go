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

package eth2exp

import (
	"context"
	"encoding/binary"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/minio/sha256-simd"

	"github.com/obolnetwork/charon/app/errors"
)

// IsAggregator returns true if the validator is the attestation aggregator for the given committee.
// Refer: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#aggregation-selection
func IsAggregator(ctx context.Context, specProvider eth2client.SpecProvider, commLen uint64, slotSig eth2p0.BLSSignature) (bool, error) {
	spec, err := specProvider.Spec(ctx)
	if err != nil {
		return false, errors.Wrap(err, "get eth2 spec")
	}

	aggsPerComm, ok := spec["TARGET_AGGREGATORS_PER_COMMITTEE"].(uint64)
	if !ok {
		return false, errors.New("invalid TARGET_AGGREGATORS_PER_COMMITTEE")
	}

	modulo := commLen / aggsPerComm
	if modulo < 1 {
		modulo = 1
	}

	h := sha256.New()
	_, err = h.Write(slotSig[:])
	if err != nil {
		return false, errors.Wrap(err, "calculate sha256")
	}

	hash := h.Sum(nil)
	lowest8bytes := hash[0:8]
	asUint64 := binary.LittleEndian.Uint64(lowest8bytes)

	return asUint64%modulo == 0, nil
}
