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
	sszMaxValidators   = 65536
)

// hashDefinition returns a config or definition hash. The config hash excludes operator ENRs and signatures
// while the definition hash includes all fields.
func hashDefinition(d Definition, configOnly bool) ([32]byte, error) {
	var hashFunc func(Definition, ssz.HashWalker, bool) error
	if isAnyVersion(d, v1_0, v1_1, v1_2) {
		hashFunc = hashDefinitionLegacy
	} else if isAnyVersion(d, v1_3, v1_4) { //nolint:revive // Early return not applicable to else if
		hashFunc = hashDefinitionV1x3or4
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
	hh.PutBytes([]byte(d.FeeRecipientAddress))

	// Field (6) 'withdrawalAddress'
	hh.PutBytes([]byte(d.WithdrawalAddress))

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
				hh.PutBytes([]byte(o.Address))

				continue
			}

			subIdx := hh.Index()

			// Field (0) 'Address'
			hh.PutBytes([]byte(o.Address))

			// Field (1) 'ENR'
			hh.PutBytes([]byte(o.ENR))

			if isV1x0(d.Version) || isV1x1(d.Version) {
				// Field (2) 'Nonce'
				hh.PutUint64(zeroNonce) // Older versions had a zero nonce
			}

			// Field (2 or 3) 'ConfigSignature'
			hh.PutBytes(o.ConfigSignature)

			// Field (3 or 4) 'ENRSignature'
			hh.PutBytes(o.ENRSignature)

			hh.Merkleize(subIdx)
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

// hashDefinitionV1x3or4 hashes the latest definition.
func hashDefinitionV1x3or4(d Definition, hh ssz.HashWalker, configOnly bool) error {
	feeRecipientAddress, err := from0xHex(d.FeeRecipientAddress, addressLen)
	if err != nil {
		return err
	}

	withdrawalAddress, err := from0xHex(d.WithdrawalAddress, addressLen)
	if err != nil {
		return err
	}

	indx := hh.Index()

	// Field (0) 'UUID' ByteList[64]
	if err := putByteList(hh, []byte(d.UUID), sszMaxUUID, "uuid"); err != nil {
		return err
	}

	// Field (1) 'Name' ByteList[256]
	if err := putByteList(hh, []byte(d.Name), sszMaxName, "name"); err != nil {
		return err
	}

	// Field (2) 'version' ByteList[16]
	if err := putByteList(hh, []byte(d.Version), sszMaxVersion, "version"); err != nil {
		return err
	}

	// Field (3) 'Timestamp' ByteList[32]
	if err := putByteList(hh, []byte(d.Timestamp), sszMaxTimestamp, "timestamp"); err != nil {
		return err
	}

	// Field (4) 'NumValidators' uint64
	hh.PutUint64(uint64(d.NumValidators))

	// Field (5) 'Threshold' uint64
	hh.PutUint64(uint64(d.Threshold))

	// Field (6) 'FeeRecipientAddress' Bytes20
	hh.PutBytes(feeRecipientAddress)

	// Field (7) 'WithdrawalAddress' Bytes20
	hh.PutBytes(withdrawalAddress)

	// Field (8) 'DKGAlgorithm' ByteList[32]
	if err := putByteList(hh, []byte(d.DKGAlgorithm), sszMaxDKGAlgorithm, "dkg_algorithm"); err != nil {
		return err
	}

	// Field (9) 'ForkVersion' Bytes4
	hh.PutBytes(d.ForkVersion)

	// Field (10) 'Operators' CompositeList[256]
	{
		operatorsIdx := hh.Index()
		num := uint64(len(d.Operators))
		for _, o := range d.Operators {
			operatorIdx := hh.Index()

			// Field (0) 'Address' Bytes20
			addrBytes, err := from0xHex(o.Address, addressLen)
			if err != nil {
				return err
			}
			hh.PutBytes(addrBytes)

			if !configOnly {
				// Field (1) 'ENR' ByteList[1024]
				if err := putByteList(hh, []byte(o.ENR), sszMaxENR, "enr"); err != nil {
					return err
				}

				// Field (2) 'ConfigSignature' Bytes65
				hh.PutBytes(o.ConfigSignature)

				// Field (3) 'ENRSignature' Bytes65
				hh.PutBytes(o.ENRSignature)
			}

			hh.Merkleize(operatorIdx)
		}
		hh.MerkleizeWithMixin(operatorsIdx, num, sszMaxOperators)
	}

	if !configOnly {
		// Field (11) 'ConfigHash' Bytes32
		hh.PutBytes(d.ConfigHash)
	}

	if !isAnyVersion(d, v1_3) {
		// Field (11 or 12) 'Creator' Composite for v1.4 and later
		creatorIdx := hh.Index()

		// Field (0) 'Address' Bytes20
		addrBytes, err := from0xHex(d.Creator.Address, addressLen)
		if err != nil {
			return err
		}
		hh.PutBytes(addrBytes)

		if !configOnly {
			// Field (1) 'ConfigSignature' Bytes65
			hh.PutBytes(d.Creator.ConfigSignature)
		}

		hh.Merkleize(creatorIdx)
	}

	hh.Merkleize(indx)

	return nil
}

// hashLock returns a lock hash.
func hashLock(l Lock) ([32]byte, error) {
	var hashFunc func(Lock, ssz.HashWalker) error
	if isV1x0(l.Version) || isV1x1(l.Version) || isV1x2(l.Version) {
		hashFunc = hashLockLegacy
	} else if isV1x3(l.Version) || isV1x4(l.Version) { //nolint:revive // Early return not applicable to else if
		hashFunc = hashLockV1x3or4
	} else {
		return [32]byte{}, errors.New("unknown version")
	}

	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)

	if err := hashFunc(l, hh); err != nil {
		return [32]byte{}, err
	}

	resp, err := hh.HashRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash root")
	}

	return resp, nil
}

// hashLockV1x3or4 hashes the latest lock hash.
func hashLockV1x3or4(l Lock, hh ssz.HashWalker) error {
	indx := hh.Index()

	// Field (0) 'Definition' Composite
	if err := hashDefinitionV1x3or4(l.Definition, hh, false); err != nil {
		return err
	}

	// Field (1) 'Validators' CompositeList[65536]
	{
		subIndx := hh.Index()
		num := uint64(len(l.Validators))
		for _, validator := range l.Validators {
			if err := hashValidatorV1x3(validator, hh); err != nil {
				return err
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, sszMaxValidators)
	}

	hh.Merkleize(indx)

	return nil
}

// hashValidatorV1x3 hashes the distributed validator.
func hashValidatorV1x3(v DistValidator, hh ssz.HashWalker) error {
	indx := hh.Index()

	// Field (0) 'PubKey' Bytes48
	hh.PutBytes(v.PubKey)

	// Field (1) 'Pubshares' CompositeList[256]
	{
		subIndx := hh.Index()
		num := uint64(len(v.PubShares))
		for _, pubshare := range v.PubShares {
			hh.PutBytes(pubshare) // Bytes48
		}
		hh.MerkleizeWithMixin(subIndx, num, sszMaxOperators)
	}

	// Field (2) 'FeeRecipientAddress' Bytes20
	hh.PutBytes(v.FeeRecipientAddress)

	hh.Merkleize(indx)

	return nil
}

// hashLockLegacy hashes the legacy lock.
func hashLockLegacy(l Lock, hh ssz.HashWalker) error {
	indx := hh.Index()

	// Field (0) 'Definition'
	if err := hashDefinitionLegacy(l.Definition, hh, false); err != nil {
		return err
	}

	// Field (1) 'Validators'
	{
		subIndx := hh.Index()
		num := uint64(len(l.Validators))
		for _, validator := range l.Validators {
			if err := hashValidatorLegacy(validator, hh); err != nil {
				return err
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, num)
	}

	hh.Merkleize(indx)

	return nil
}

// hashValidatorLegacy hashes the legacy distributed validator.
func hashValidatorLegacy(v DistValidator, hh ssz.HashWalker) error {
	indx := hh.Index()

	// Field (0) 'PubKey'
	hh.PutBytes([]byte(to0xHex(v.PubKey)))

	// Field (1) 'Pubshares'
	{
		subIndx := hh.Index()
		num := uint64(len(v.PubShares))
		for _, pubshare := range v.PubShares {
			hh.PutBytes(pubshare)
		}
		hh.MerkleizeWithMixin(subIndx, num, num)
	}

	// Field (2) 'FeeRecipientAddress'
	hh.PutBytes([]byte(to0xHex(v.FeeRecipientAddress)))

	hh.Merkleize(indx)

	return nil
}
