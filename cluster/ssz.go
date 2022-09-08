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

package cluster

import (
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
)

const (
	sszMaxENR          = 1024
	sszMaxName         = 256
	sszMaxUUID         = 64
	sszMaxVersion      = 16
	sszMaxTimestamp    = 32
	sszMaxDKGAlgorithm = 32
	sszMaxOperators    = 256
)

// hashDefinition returns a config or definition hash. The config hash excludes operator ENRs and signatures
// while the definition hash includes all fields.
func hashDefinition(d Definition, configOnly bool) ([32]byte, error) {
	var hashFunc func(Definition, ssz.HashWalker, bool) error
	if isJSONv1x0(d.Version) || isJSONv1x1(d.Version) || isJSONv1x2(d.Version) {
		hashFunc = hashDefinitionLegacy
	} else if isJSONv1x3(d.Version) { //nolint:revive // Early return not applicable to else if
		hashFunc = hashDefinitionV1x3
	} else {
		return [32]byte{}, errors.New("unknown version")
	}

	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)

	if err := hashFunc(d, hh, configOnly); err != nil {
		return [32]byte{}, err
	}

	resp, err := hh.HashRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash root")
	}

	return resp, nil
}

// hashLegaacy hashes a legacy definition.
func hashDefinitionLegacy(d Definition, hh ssz.HashWalker, configOnly bool) error {
	indx := hh.Index()

	// Field (0) 'uuid'
	hh.PutBytes([]byte(d.UUID))

	// Field (1) 'name'
	hh.PutBytes([]byte(d.Name))

	// Field (2) 'version'
	hh.PutBytes([]byte(d.Version))

	// Field (3) 'numValidators'
	hh.PutUint64(uint64(d.NumValidators))

	// Field (4) 'threshold'
	hh.PutUint64(uint64(d.Threshold))

	// Field (5) 'feeRecipientAddress'
	hh.PutBytes([]byte(to0xHex(d.FeeRecipientAddress)))

	// Field (6) 'withdrawalAddress'
	hh.PutBytes([]byte(to0xHex(d.WithdrawalAddress)))

	// Field (7) 'dkgAlgorithm'
	hh.PutBytes([]byte(d.DKGAlgorithm))

	// Field (8) 'forkVersion'
	hh.PutBytes([]byte(to0xHex(d.ForkVersion)))

	// Field (9) 'addresses'
	{
		subIndx := hh.Index()
		num := uint64(len(d.Operators))
		for _, o := range d.Operators {
			if configOnly {
				hh.PutBytes([]byte(to0xHex(o.Address)))
			} else {
				subIdx := hh.Index()

				// Field (0) 'Address'
				hh.PutBytes([]byte(to0xHex(o.Address)))

				// Field (1) 'ENR'
				hh.PutBytes([]byte(o.ENR))

				if isJSONv1x0(d.Version) || isJSONv1x1(d.Version) {
					// Field (2) 'Nonce'
					hh.PutUint64(zeroNonce) // Older versions had a zero nonce
				}

				// Field (2 or 3) 'ConfigSignature'
				hh.PutBytes(o.ConfigSignature)

				// Field (3 or 4) 'ENRSignature'
				hh.PutBytes(o.ENRSignature)

				hh.Merkleize(subIdx)
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, num)
	}

	// Field (10) 'timestamp' (optional for backwards compatibility)
	if configOnly {
		// TODO(corver): This is a bug, config_hash should use the same check as definitino hash below.
		if d.Timestamp != "" {
			hh.PutBytes([]byte(d.Timestamp))
		}
	} else {
		if d.Version != v1_0 {
			hh.PutBytes([]byte(d.Timestamp))
		}
	}

	hh.Merkleize(indx)

	return nil
}

// hashDefinitionV1x3 hashes the latest definition.
func hashDefinitionV1x3(d Definition, hh ssz.HashWalker, configOnly bool) error {
	indx := hh.Index()

	// Field (0) 'UUID' ByteList[64]
	if err := putByteList(hh, []byte(d.UUID), sszMaxUUID); err != nil {
		return err
	}

	// Field (1) 'Name' ByteList[256]
	if err := putByteList(hh, []byte(d.Name), sszMaxName); err != nil {
		return err
	}

	// Field (2) 'version' ByteList[16]
	if err := putByteList(hh, []byte(d.Version), sszMaxVersion); err != nil {
		return err
	}

	// Field (3) 'Timestamp' ByteList[32]
	if err := putByteList(hh, []byte(d.Timestamp), sszMaxTimestamp); err != nil {
		return err
	}

	// Field (4) 'NumValidators' uint64
	hh.PutUint64(uint64(d.NumValidators))

	// Field (5) 'Threshold' uint64
	hh.PutUint64(uint64(d.Threshold))

	// Field (6) 'FeeRecipientAddress' Bytes20
	hh.PutBytes(d.FeeRecipientAddress)

	// Field (7) 'WithdrawalAddress' Bytes20
	hh.PutBytes(d.WithdrawalAddress)

	// Field (8) 'DKGAlgorithm' ByteList[32]
	if err := putByteList(hh, []byte(d.DKGAlgorithm), sszMaxDKGAlgorithm); err != nil {
		return err
	}

	// Field (9) 'ForkVersion' Bytes4
	hh.PutBytes(d.ForkVersion)

	// Field (10) 'Operators' CompositeList[256]
	{
		subIndx := hh.Index()
		num := uint64(len(d.Operators))
		for _, o := range d.Operators {
			indx := hh.Index()

			// Field (0) 'Address' Bytes20
			hh.PutBytes(o.Address)

			if !configOnly {
				// Field (1) 'ENR' ByteList[1024]
				if err := putByteList(hh, []byte(o.ENR), sszMaxENR); err != nil {
					return err
				}

				// Field (2) 'ConfigSignature' Bytes32
				hh.PutBytes(o.ConfigSignature)

				// Field (3) 'ENRSignature' Bytes32
				hh.PutBytes(o.ENRSignature)
			}

			hh.Merkleize(indx)
		}
		hh.MerkleizeWithMixin(subIndx, num, sszMaxOperators)
	}

	if !configOnly {
		// Field 11) 'ConfigHash' Bytes32
		hh.PutBytes(d.ConfigHash)
	}

	hh.Merkleize(indx)

	return nil
}
