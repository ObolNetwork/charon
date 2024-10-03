// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

const (
	sszMaxENR            = 1024
	sszMaxName           = 256
	sszMaxUUID           = 64
	sszMaxVersion        = 16
	sszMaxTimestamp      = 32
	sszMaxDKGAlgorithm   = 32
	sszMaxOperators      = 256
	sszMaxValidators     = 65536
	sszMaxDepositAmounts = 256
	sszLenForkVersion    = 4
	sszLenK1Sig          = 65
	sszLenBLSSig         = 96
	sszLenHash           = 32
	sszLenWithdrawCreds  = 32
	sszLenPubKey         = 48
)

// getDefinitionHashFunc returns the function to hash a definition based on the provided version.
func getDefinitionHashFunc(version string) (func(Definition, ssz.HashWalker, bool) error, error) {
	if isAnyVersion(version, v1_0, v1_1, v1_2) {
		return hashDefinitionLegacy, nil
	} else if isAnyVersion(version, v1_3, v1_4) {
		return hashDefinitionV1x3or4, nil
	} else if isAnyVersion(version, v1_5, v1_6, v1_7) {
		return hashDefinitionV1x5to7, nil
	} else if isAnyVersion(version, v1_8) {
		return hashDefinitionV1x8, nil
	} else if isAnyVersion(version, v1_9) {
		return hashDefinitionV1x9orLater, nil
	}

	return nil, errors.New("unknown version", z.Str("version", version))
}

// hashDefinition returns a config or definition hash. The config hash excludes operator ENRs and signatures
// while the definition hash includes all fields.
func hashDefinition(d Definition, configOnly bool) ([32]byte, error) {
	hashFunc, err := getDefinitionHashFunc(d.Version)
	if err != nil {
		return [32]byte{}, err
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
	vaddrs, err := d.LegacyValidatorAddresses()
	if err != nil {
		return err
	}

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
	hh.PutBytes([]byte(vaddrs.FeeRecipientAddress))

	// Field (6) 'withdrawalAddress'
	hh.PutBytes([]byte(vaddrs.WithdrawalAddress))

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

			if isAnyVersion(d.Version, v1_0, v1_1) {
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
	vaddrs, err := d.LegacyValidatorAddresses()
	if err != nil {
		return err
	}

	feeRecipientAddress, err := from0xHex(vaddrs.FeeRecipientAddress, addressLen)
	if err != nil {
		return err
	}

	withdrawalAddress, err := from0xHex(vaddrs.WithdrawalAddress, addressLen)
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

	// Field (7) 'WithdrawalAddrs' Bytes20
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

	if !isV1x3(d.Version) {
		// Field (11) 'Creator' Composite for v1.4 and later
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

	if !configOnly {
		// Field (12) 'ConfigHash' Bytes32
		hh.PutBytes(d.ConfigHash)
	}

	hh.Merkleize(indx)

	return nil
}

// hashDefinitionV1x5to7 hashes the new definition.
func hashDefinitionV1x5to7(d Definition, hh ssz.HashWalker, configOnly bool) error {
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

	// Field (6) 'DKGAlgorithm' ByteList[32]
	if err := putByteList(hh, []byte(d.DKGAlgorithm), sszMaxDKGAlgorithm, "dkg_algorithm"); err != nil {
		return err
	}

	// Field (7) 'ForkVersion' Bytes4
	if err := putBytesN(hh, d.ForkVersion, sszLenForkVersion); err != nil {
		return err
	}

	// Field (8) 'Operators' CompositeList[256]
	{
		operatorsIdx := hh.Index()
		num := uint64(len(d.Operators))
		for _, o := range d.Operators {
			operatorIdx := hh.Index()

			// Field (0) 'Address' Bytes20
			if err := putHexBytes20(hh, o.Address); err != nil {
				return err
			}

			if !configOnly {
				// Field (1) 'ENR' ByteList[1024]
				if err := putByteList(hh, []byte(o.ENR), sszMaxENR, "enr"); err != nil {
					return err
				}

				// Field (2) 'ConfigSignature' Bytes65
				if err := putBytesN(hh, o.ConfigSignature, sszLenK1Sig); err != nil {
					return err
				}

				// Field (3) 'ENRSignature' Bytes65
				if err := putBytesN(hh, o.ENRSignature, sszLenK1Sig); err != nil {
					return err
				}
			}

			hh.Merkleize(operatorIdx)
		}
		hh.MerkleizeWithMixin(operatorsIdx, num, sszMaxOperators)
	}

	// Field (9) 'Creator' Composite for v1.4 and later
	{
		creatorIdx := hh.Index()

		// Field (0) 'Address' Bytes20
		if err := putHexBytes20(hh, d.Creator.Address); err != nil {
			return err
		}

		if !configOnly {
			// Field (1) 'ConfigSignature' Bytes65
			if err := putBytesN(hh, d.Creator.ConfigSignature, sszLenK1Sig); err != nil {
				return err
			}
		}
		hh.Merkleize(creatorIdx)
	}

	// Field (10) 'ValidatorAddresses' CompositeList[65536]
	{
		validatorsIdx := hh.Index()
		num := uint64(len(d.ValidatorAddresses))
		for _, v := range d.ValidatorAddresses {
			validatorIdx := hh.Index()

			// Field (0) 'FeeRecipientAddress' Bytes20
			if err := putHexBytes20(hh, v.FeeRecipientAddress); err != nil {
				return err
			}

			// Field (1) 'WithdrawalAddrs' Bytes20
			if err := putHexBytes20(hh, v.WithdrawalAddress); err != nil {
				return err
			}

			hh.Merkleize(validatorIdx)
		}
		hh.MerkleizeWithMixin(validatorsIdx, num, sszMaxValidators)
	}

	if !configOnly {
		// Field (11) 'ConfigHash' Bytes32
		if err := putBytesN(hh, d.ConfigHash, sszLenHash); err != nil {
			return err
		}
	}

	hh.Merkleize(indx)

	return nil
}

// hashDefinitionV1x8 hashes the new definition.
func hashDefinitionV1x8(d Definition, hh ssz.HashWalker, configOnly bool) error {
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

	// Field (6) 'DKGAlgorithm' ByteList[32]
	if err := putByteList(hh, []byte(d.DKGAlgorithm), sszMaxDKGAlgorithm, "dkg_algorithm"); err != nil {
		return err
	}

	// Field (7) 'ForkVersion' Bytes4
	if err := putBytesN(hh, d.ForkVersion, sszLenForkVersion); err != nil {
		return err
	}

	// Field (8) 'Operators' CompositeList[256]
	{
		operatorsIdx := hh.Index()
		num := uint64(len(d.Operators))
		for _, o := range d.Operators {
			operatorIdx := hh.Index()

			// Field (0) 'Address' Bytes20
			if err := putHexBytes20(hh, o.Address); err != nil {
				return err
			}

			if !configOnly {
				// Field (1) 'ENR' ByteList[1024]
				if err := putByteList(hh, []byte(o.ENR), sszMaxENR, "enr"); err != nil {
					return err
				}

				// Field (2) 'ConfigSignature' Bytes65
				if err := putBytesN(hh, o.ConfigSignature, sszLenK1Sig); err != nil {
					return err
				}

				// Field (3) 'ENRSignature' Bytes65
				if err := putBytesN(hh, o.ENRSignature, sszLenK1Sig); err != nil {
					return err
				}
			}

			hh.Merkleize(operatorIdx)
		}
		hh.MerkleizeWithMixin(operatorsIdx, num, sszMaxOperators)
	}

	// Field (9) 'Creator' Composite for v1.4 and later
	{
		creatorIdx := hh.Index()

		// Field (0) 'Address' Bytes20
		if err := putHexBytes20(hh, d.Creator.Address); err != nil {
			return err
		}

		if !configOnly {
			// Field (1) 'ConfigSignature' Bytes65
			if err := putBytesN(hh, d.Creator.ConfigSignature, sszLenK1Sig); err != nil {
				return err
			}
		}
		hh.Merkleize(creatorIdx)
	}

	// Field (10) 'ValidatorAddresses' CompositeList[65536]
	{
		validatorsIdx := hh.Index()
		num := uint64(len(d.ValidatorAddresses))
		for _, v := range d.ValidatorAddresses {
			validatorIdx := hh.Index()

			// Field (0) 'FeeRecipientAddress' Bytes20
			if err := putHexBytes20(hh, v.FeeRecipientAddress); err != nil {
				return err
			}

			// Field (1) 'WithdrawalAddrs' Bytes20
			if err := putHexBytes20(hh, v.WithdrawalAddress); err != nil {
				return err
			}

			hh.Merkleize(validatorIdx)
		}
		hh.MerkleizeWithMixin(validatorsIdx, num, sszMaxValidators)
	}

	// Field (11) 'DepositAmounts' uint64[256]
	{
		hasher, ok := hh.(*ssz.Hasher)
		if !ok {
			return errors.New("invalid hasher type")
		}
		var amounts64 []uint64
		for _, amount := range d.DepositAmounts {
			amounts64 = append(amounts64, uint64(amount))
		}
		hasher.PutUint64Array(amounts64, sszMaxDepositAmounts)
	}

	if !configOnly {
		// Field (12) 'ConfigHash' Bytes32
		if err := putBytesN(hh, d.ConfigHash, sszLenHash); err != nil {
			return err
		}
	}

	hh.Merkleize(indx)

	return nil
}

// hashDefinitionV1x9OrLater hashes the new definition.
func hashDefinitionV1x9orLater(d Definition, hh ssz.HashWalker, configOnly bool) error {
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

	// Field (6) 'DKGAlgorithm' ByteList[32]
	if err := putByteList(hh, []byte(d.DKGAlgorithm), sszMaxDKGAlgorithm, "dkg_algorithm"); err != nil {
		return err
	}

	// Field (7) 'ForkVersion' Bytes4
	if err := putBytesN(hh, d.ForkVersion, sszLenForkVersion); err != nil {
		return err
	}

	// Field (8) 'Operators' CompositeList[256]
	{
		operatorsIdx := hh.Index()
		num := uint64(len(d.Operators))
		for _, o := range d.Operators {
			operatorIdx := hh.Index()

			// Field (0) 'Address' Bytes20
			if err := putHexBytes20(hh, o.Address); err != nil {
				return err
			}

			if !configOnly {
				// Field (1) 'ENR' ByteList[1024]
				if err := putByteList(hh, []byte(o.ENR), sszMaxENR, "enr"); err != nil {
					return err
				}

				// Field (2) 'ConfigSignature' Bytes65
				if err := putBytesN(hh, o.ConfigSignature, sszLenK1Sig); err != nil {
					return err
				}

				// Field (3) 'ENRSignature' Bytes65
				if err := putBytesN(hh, o.ENRSignature, sszLenK1Sig); err != nil {
					return err
				}
			}

			hh.Merkleize(operatorIdx)
		}
		hh.MerkleizeWithMixin(operatorsIdx, num, sszMaxOperators)
	}

	// Field (9) 'Creator' Composite for v1.4 and later
	{
		creatorIdx := hh.Index()

		// Field (0) 'Address' Bytes20
		if err := putHexBytes20(hh, d.Creator.Address); err != nil {
			return err
		}

		if !configOnly {
			// Field (1) 'ConfigSignature' Bytes65
			if err := putBytesN(hh, d.Creator.ConfigSignature, sszLenK1Sig); err != nil {
				return err
			}
		}
		hh.Merkleize(creatorIdx)
	}

	// Field (10) 'ValidatorAddresses' CompositeList[65536]
	{
		validatorsIdx := hh.Index()
		num := uint64(len(d.ValidatorAddresses))
		for _, v := range d.ValidatorAddresses {
			validatorIdx := hh.Index()

			// Field (0) 'FeeRecipientAddress' Bytes20
			if err := putHexBytes20(hh, v.FeeRecipientAddress); err != nil {
				return err
			}

			// Field (1) 'WithdrawalAddrs' Bytes20
			if err := putHexBytes20(hh, v.WithdrawalAddress); err != nil {
				return err
			}

			hh.Merkleize(validatorIdx)
		}
		hh.MerkleizeWithMixin(validatorsIdx, num, sszMaxValidators)
	}

	// Field (11) 'DepositAmounts' uint64[256]
	{
		hasher, ok := hh.(*ssz.Hasher)
		if !ok {
			return errors.New("invalid hasher type")
		}
		var amounts64 []uint64
		for _, amount := range d.DepositAmounts {
			amounts64 = append(amounts64, uint64(amount))
		}
		hasher.PutUint64Array(amounts64, sszMaxDepositAmounts)
	}

	// Field (12) 'ConsensusProtocol' ByteList[256]
	if err := putByteList(hh, []byte(d.ConsensusProtocol), sszMaxName, "consensus_protocol"); err != nil {
		return err
	}

	if !configOnly {
		// Field (13) 'ConfigHash' Bytes32
		if err := putBytesN(hh, d.ConfigHash, sszLenHash); err != nil {
			return err
		}
	}

	hh.Merkleize(indx)

	return nil
}

// hashLock returns a lock hash.
func hashLock(l Lock) ([32]byte, error) {
	var hashFunc func(Lock, ssz.HashWalker) error
	if isAnyVersion(l.Version, v1_0, v1_1, v1_2) {
		hashFunc = hashLockLegacy
	} else if isAnyVersion(l.Version, v1_3, v1_4, v1_5, v1_6, v1_7, v1_8, v1_9) {
		hashFunc = hashLockV1x3orLater
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

// hashLockV1x3orLater hashes the version v1.3 or later.
func hashLockV1x3orLater(l Lock, hh ssz.HashWalker) error {
	indx := hh.Index()

	defHashFunc, err := getDefinitionHashFunc(l.Version)
	if err != nil {
		return err
	}

	valHashFunc, err := getValidatorHashFunc(l.Version)
	if err != nil {
		return err
	}

	// Field (0) 'Definition' Composite
	if err := defHashFunc(l.Definition, hh, false); err != nil {
		return err
	}

	// Field (1) 'Validators' CompositeList[65536]
	{
		subIndx := hh.Index()
		num := uint64(len(l.Validators))
		for _, validator := range l.Validators {
			if err := valHashFunc(validator, hh, l.Version); err != nil {
				return err
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, sszMaxValidators)
	}

	hh.Merkleize(indx)

	return nil
}

// getDefinitionHashFunc returns the function to hash a definition based on the provided version.
func getValidatorHashFunc(version string) (func(DistValidator, ssz.HashWalker, string) error, error) {
	if isAnyVersion(version, v1_3, v1_4) {
		return hashValidatorV1x3Or4, nil
	} else if isAnyVersion(version, v1_5, v1_6, v1_7) {
		return hashValidatorV1x5to7, nil
	} else if isAnyVersion(version, v1_8, v1_9) {
		return hashValidatorV1x8OrLater, nil
	}

	return nil, errors.New("unknown version", z.Str("version", version))
}

func hashValidatorPubsharesField(v DistValidator, hh ssz.HashWalker) error {
	subIndx := hh.Index()
	num := uint64(len(v.PubShares))

	for _, pubshare := range v.PubShares {
		if err := putBytesN(hh, pubshare, sszLenPubKey); err != nil {
			return err
		}
	}

	hh.MerkleizeWithMixin(subIndx, num, sszMaxOperators)

	return nil
}

// hashValidatorV1x3Or4 hashes the distributed validator v1.3 or v1.4.
func hashValidatorV1x3Or4(v DistValidator, hh ssz.HashWalker, _ string) error {
	indx := hh.Index()

	// Field (0) 'PubKey' Bytes48
	hh.PutBytes(v.PubKey)

	// Field (1) 'Pubshares' CompositeList[256]
	if err := hashValidatorPubsharesField(v, hh); err != nil {
		return err
	}

	// Field (2) 'FeeRecipientAddress' Bytes20
	hh.PutBytes(nil)

	hh.Merkleize(indx)

	return nil
}

// hashValidatorV1x5to7 hashes the distributed validator v1.5 - v1.7.
func hashValidatorV1x5to7(v DistValidator, hh ssz.HashWalker, version string) error {
	indx := hh.Index()

	// Field (0) 'PubKey' Bytes48
	if err := putBytesN(hh, v.PubKey, sszLenPubKey); err != nil {
		return err
	}

	// Field (1) 'Pubshares' CompositeList[256]
	if err := hashValidatorPubsharesField(v, hh); err != nil {
		return err
	}

	depositHashFunc, err := getDepositDataHashFunc(version)
	if err != nil {
		return err
	}

	// Field (2) 'DepositData' Composite
	var dd DepositData
	if len(v.PartialDepositData) > 0 {
		dd = v.PartialDepositData[0]
	}

	if err := depositHashFunc(dd, hh); err != nil {
		return err
	}

	regHashFunc, err := getRegistrationHashFunc(version)
	if err != nil {
		return err
	}

	// Field (3) 'BuilderRegistration' Composite
	if err := regHashFunc(v.BuilderRegistration, hh); err != nil {
		return err
	}

	hh.Merkleize(indx)

	return nil
}

// hashValidatorV1x8OrLater hashes the distributed validator v1.8 or later.
func hashValidatorV1x8OrLater(v DistValidator, hh ssz.HashWalker, version string) error {
	indx := hh.Index()

	// Field (0) 'PubKey' Bytes48
	if err := putBytesN(hh, v.PubKey, sszLenPubKey); err != nil {
		return err
	}

	// Field (1) 'Pubshares' CompositeList[256]
	if err := hashValidatorPubsharesField(v, hh); err != nil {
		return err
	}

	depositHashFunc, err := getDepositDataHashFunc(version)
	if err != nil {
		return err
	}

	regHashFunc, err := getRegistrationHashFunc(version)
	if err != nil {
		return err
	}

	// Field (2) 'PartialDepositData' Composite[256]
	{
		pddIndx := hh.Index()
		num := uint64(len(v.PartialDepositData))
		for _, dd := range v.PartialDepositData {
			ddIndx := hh.Index()
			if err := depositHashFunc(dd, hh); err != nil {
				return err
			}
			hh.Merkleize(ddIndx)
		}
		hh.MerkleizeWithMixin(pddIndx, num, sszMaxDepositAmounts)
	}

	// Field (3) 'BuilderRegistration' Composite
	if err := regHashFunc(v.BuilderRegistration, hh); err != nil {
		return err
	}

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

	// Field (1) 'ValidatorAddresses'
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
	hh.PutBytes(nil)

	hh.Merkleize(indx)

	return nil
}

// getDepositDataHashFunc returns the function to hash a deposit data based on the provided version.
func getDepositDataHashFunc(version string) (func(DepositData, ssz.HashWalker) error, error) {
	if isAnyVersion(version, v1_0, v1_1, v1_2, v1_3, v1_4, v1_5) {
		// Noop hash function for v1.0 to v1.5 that do not support deposit data.
		return func(DepositData, ssz.HashWalker) error { return nil }, nil
	} else if isAnyVersion(version, v1_6) {
		return hashDepositDataV1x6, nil
	} else if isAnyVersion(version, v1_7, v1_8, v1_9) {
		return hashDepositDataV1x7OrLater, nil
	}

	return nil, errors.New("unknown version", z.Str("version", version))
}

// getRegistrationHashFunc returns the function to hash a BuilderRegistration based on the provided version.
func getRegistrationHashFunc(version string) (func(BuilderRegistration, ssz.HashWalker) error, error) {
	if isAnyVersion(version, v1_0, v1_1, v1_2, v1_3, v1_4, v1_5, v1_6) {
		// Noop hash function for v1.0 to v1.6 that do not support builder registration.
		return func(BuilderRegistration, ssz.HashWalker) error { return nil }, nil
	} else if isAnyVersion(version, v1_7, v1_8, v1_9) {
		return hashBuilderRegistration, nil
	}

	return nil, errors.New("unknown version", z.Str("version", version))
}

// hashDepositDataV1x6 hashes the deposit data for version v1.6.0.
// Note: There is a bug in this function where we missed merkleize step of DepositData.
func hashDepositDataV1x6(d DepositData, hh ssz.HashWalker) error {
	// Field (0) 'PubKey' Bytes48
	if err := putBytesN(hh, d.PubKey, sszLenPubKey); err != nil {
		return err
	}

	// Field (1) 'WithdrawalCredentials' Bytes32
	if err := putBytesN(hh, d.WithdrawalCredentials, sszLenWithdrawCreds); err != nil {
		return err
	}

	// Field (2) 'Amount' uint64
	hh.PutUint64(uint64(d.Amount))

	// Field (3) 'Signature' Bytes96
	return putBytesN(hh, d.Signature, sszLenBLSSig)
}

// hashDepositDataV1x7OrLater hashes the latest deposit data.
func hashDepositDataV1x7OrLater(d DepositData, hh ssz.HashWalker) error {
	indx := hh.Index()

	// Field (0) 'PubKey' Bytes48
	if err := putBytesN(hh, d.PubKey, sszLenPubKey); err != nil {
		return err
	}

	// Field (1) 'WithdrawalCredentials' Bytes32
	if err := putBytesN(hh, d.WithdrawalCredentials, sszLenWithdrawCreds); err != nil {
		return err
	}

	// Field (2) 'Amount' uint64
	hh.PutUint64(uint64(d.Amount))

	// Field (3) 'Signature' Bytes96
	if err := putBytesN(hh, d.Signature, sszLenBLSSig); err != nil {
		return err
	}

	hh.Merkleize(indx)

	return nil
}

// hashBuilderRegistration hashes the latest builder registration.
func hashBuilderRegistration(b BuilderRegistration, hh ssz.HashWalker) error {
	indx := hh.Index()

	// Field (0) 'Message' Composite
	if err := hashRegistration(b.Message, hh); err != nil {
		return err
	}

	// Field (1) 'Signature' Bytes96
	if err := putBytesN(hh, b.Signature, sszLenBLSSig); err != nil {
		return err
	}

	hh.Merkleize(indx)

	return nil
}

// hashRegistration hashes the latest deposit data.
func hashRegistration(r Registration, hh ssz.HashWalker) error {
	indx := hh.Index()

	// Field (0) 'FeeRecipient'
	hh.PutBytes(r.FeeRecipient)

	// Field (1) 'GasLimit' uint64
	hh.PutUint64(uint64(r.GasLimit))

	// Field (2) 'Timestamp' uint64
	hh.PutUint64(uint64(r.Timestamp.Unix()))

	// Field (3) 'PubKey' Bytes48
	if err := putBytesN(hh, r.PubKey, sszLenPubKey); err != nil {
		return err
	}

	hh.Merkleize(indx)

	return nil
}
