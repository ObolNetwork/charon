// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2exp

import (
	"context"
	"crypto/sha256"
	"encoding/binary"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
)

// IsAttAggregator returns true if the validator is the attestation aggregator for the given committee.
// Refer: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#aggregation-selection
func IsAttAggregator(ctx context.Context, specProvider eth2client.SpecProvider, commLen uint64, slotSig eth2p0.BLSSignature) (bool, error) {
	resp, err := specProvider.Spec(ctx)
	if err != nil {
		return false, errors.Wrap(err, "get eth2 spec")
	}
	spec := resp.Data

	aggsPerComm, ok := spec["TARGET_AGGREGATORS_PER_COMMITTEE"].(uint64)
	if !ok {
		return false, errors.New("invalid TARGET_AGGREGATORS_PER_COMMITTEE")
	}

	modulo := commLen / aggsPerComm
	if modulo < 1 {
		modulo = 1
	}

	return hashModulo(slotSig, modulo)
}

// IsSyncCommAggregator returns true if the validator is the aggregator for the provided sync subcommittee.
// Refer: https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#aggregation-selection
func IsSyncCommAggregator(ctx context.Context, specProvider eth2client.SpecProvider, sig eth2p0.BLSSignature) (bool, error) {
	resp, err := specProvider.Spec(ctx)
	if err != nil {
		return false, errors.Wrap(err, "get eth2 spec")
	}
	spec := resp.Data

	commSize, ok := spec["SYNC_COMMITTEE_SIZE"].(uint64)
	if !ok {
		return false, errors.New("invalid SYNC_COMMITTEE_SIZE")
	}

	commSubnetCount, ok := spec["SYNC_COMMITTEE_SUBNET_COUNT"].(uint64)
	if !ok {
		return false, errors.New("invalid SYNC_COMMITTEE_SUBNET_COUNT")
	}

	aggsPerComm, ok := spec["TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE"].(uint64)
	if !ok {
		return false, errors.New("invalid TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE")
	}

	modulo := commSize / commSubnetCount / aggsPerComm
	if modulo < 1 {
		modulo = 1
	}

	return hashModulo(sig, modulo)
}

// hashModulo returns true if the first 8 bytes of the sha256 hashModulo of the input signature is divisible by the provided modulo.
func hashModulo(sig eth2p0.BLSSignature, modulo uint64) (bool, error) {
	h := sha256.New()
	_, err := h.Write(sig[:])
	if err != nil {
		return false, errors.Wrap(err, "calculate sha256")
	}

	hash := h.Sum(nil)
	lowest8bytes := hash[0:8]
	asUint64 := binary.LittleEndian.Uint64(lowest8bytes)

	return asUint64%modulo == 0, nil
}
