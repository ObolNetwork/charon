// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package proposerconfig

import (
	"bytes"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"

	"github.com/pk910/dynamic-ssz/hasher"
	"github.com/pk910/dynamic-ssz/sszutils"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

const (
	sszMaxVersion  = 16
	sszMaxEntries  = 65536
	sszMaxBuilders = 32
	sszLenHash     = 32
	sszLenPubKey   = 48
	sszLenAddress  = 20
)

// hashDocument returns a revision hash.
func hashDocument(d Document) ([32]byte, error) {
	hh := hasher.DefaultHasherPool.Get()
	defer hasher.DefaultHasherPool.Put(hh)

	err := hashDocumentV1(d, hh)
	if err != nil {
		return [32]byte{}, err
	}

	resp, err := hh.HashRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash root")
	}

	return resp, nil
}

// hashDocumentV1 hashes the version v1 document. Fields the edit command cannot set have no place in it, so a
// document setting them doesn't hash.
func hashDocumentV1(d Document, hh sszutils.HashWalker) error {
	indx := hh.Index()

	// Field (0) 'Version' ByteList[16]
	err := putByteList(hh, []byte(d.Version), sszMaxVersion, "version")
	if err != nil {
		return err
	}

	// Field (1) 'LockHash' Bytes32
	err = putBytesN(hh, d.LockHash, sszLenHash, "lock_hash")
	if err != nil {
		return err
	}

	// Field (2) 'Revision' uint64
	hh.PutUint64(d.Revision)

	// Field (3) 'DefaultConfig' Composite
	err = hashSettings(d.Config.DefaultConfig, hh)
	if err != nil {
		return err
	}

	// Field (4) 'ProposerConfig' CompositeList[65536], sorted by pubkey so the hash doesn't depend on map order
	{
		subIndx := hh.Index()

		entries, err := sortedEntries(d.Config.ProposerConfig)
		if err != nil {
			return err
		}

		for _, e := range entries {
			err := hashEntry(e, hh)
			if err != nil {
				return err
			}
		}

		hh.MerkleizeWithMixin(subIndx, uint64(len(entries)), sszMaxEntries)
	}

	hh.Merkleize(indx)

	return nil
}

// hashSettings hashes the default config.
func hashSettings(s Settings, hh sszutils.HashWalker) error {
	indx := hh.Index()

	// Field (0) 'FeeRecipient' ByteList[20], empty for none as in v1.0 and v1.1 locks
	var fee []byte

	if s.FeeRecipient != "" {
		var err error

		fee, err = from0xHex(s.FeeRecipient, sszLenAddress, "fee_recipient")
		if err != nil {
			return err
		}
	}

	err := putByteList(hh, fee, sszLenAddress, "fee_recipient")
	if err != nil {
		return err
	}

	// Field (1) 'GasLimit' uint64
	err = putUint64String(hh, s.GasLimit, "gas_limit")
	if err != nil {
		return err
	}

	// Field (2) 'Builder' CompositeList[1], empty without a builder
	{
		subIndx := hh.Index()

		var num uint64

		if s.Builder != nil {
			num = 1

			err := hashBuilder(*s.Builder, hh)
			if err != nil {
				return err
			}
		}

		hh.MerkleizeWithMixin(subIndx, num, 1)
	}

	hh.Merkleize(indx)

	return nil
}

// hashBuilder hashes the default config's builder.
func hashBuilder(b Builder, hh sszutils.HashWalker) error {
	indx := hh.Index()

	// Field (0) 'MinBid' uint64
	err := putUint64String(hh, b.MinBid, "min_bid")
	if err != nil {
		return err
	}

	// Field (1) 'BuilderBoostFactor' uint64
	err = putUint64String(hh, b.BuilderBoostFactor, "builder_boost_factor")
	if err != nil {
		return err
	}

	// Field (2) 'MaxExecutionPayment' uint64
	err = putUint64String(hh, b.MaxExecutionPayment, "max_execution_payment")
	if err != nil {
		return err
	}

	// Field (3) 'Builders' List[ByteList[2048], 32] of the builder URLs
	{
		subIndx := hh.Index()

		num := uint64(len(b.Builders))
		if num > sszMaxBuilders {
			return errors.New("incorrect list size", z.Str("field", "builders"))
		}

		for _, e := range b.Builders {
			if e.MinBid != "" || e.BuilderBoostFactor != "" || e.MaxExecutionPayment != "" {
				return errors.New("builder entry sets more than url")
			}

			err := putByteList(hh, []byte(e.URL), core.MaxBuilderURLSize, "builder_url")
			if err != nil {
				return err
			}
		}

		hh.MerkleizeWithMixin(subIndx, num, sszMaxBuilders)
	}

	hh.Merkleize(indx)

	return nil
}

// entry is a decoded proposer_config entry.
type entry struct {
	PubKey       []byte
	FeeRecipient []byte
}

// hashEntry hashes a proposer_config entry.
func hashEntry(e entry, hh sszutils.HashWalker) error {
	indx := hh.Index()

	// Field (0) 'PubKey' Bytes48
	err := putBytesN(hh, e.PubKey, sszLenPubKey, "pubkey")
	if err != nil {
		return err
	}

	// Field (1) 'FeeRecipient' Bytes20
	err = putBytesN(hh, e.FeeRecipient, sszLenAddress, "fee_recipient")
	if err != nil {
		return err
	}

	hh.Merkleize(indx)

	return nil
}

// sortedEntries returns the proposer_config entries decoded and sorted by pubkey.
func sortedEntries(entries map[string]Settings) ([]entry, error) {
	if len(entries) > sszMaxEntries {
		return nil, errors.New("incorrect list size", z.Str("field", "proposer_config"))
	}

	resp := make([]entry, 0, len(entries))

	for key, s := range entries {
		if s.GasLimit != "" || s.Builder != nil {
			return nil, errors.New("entry sets more than fee_recipient", z.Str("pubkey", key))
		}

		pubkey, err := from0xHex(key, sszLenPubKey, "pubkey")
		if err != nil {
			return nil, err
		}

		fee, err := from0xHex(s.FeeRecipient, sszLenAddress, "fee_recipient")
		if err != nil {
			return nil, errors.Wrap(err, "proposer_config entry", z.Str("pubkey", key))
		}

		resp = append(resp, entry{PubKey: pubkey, FeeRecipient: fee})
	}

	slices.SortFunc(resp, func(a, b entry) int { return bytes.Compare(a.PubKey, b.PubKey) })

	return resp, nil
}

// putByteList appends b as a ssz byte list with the given limit.
func putByteList(h sszutils.HashWalker, b []byte, limit int, field string) error {
	elemIndx := h.Index()

	byteLen := len(b)
	if byteLen > limit {
		return errors.New("incorrect list size", z.Str("field", field))
	}

	h.AppendBytes32(b)
	h.MerkleizeWithMixin(elemIndx, uint64(byteLen), uint64(limit+31)/32)

	return nil
}

// putBytesN appends b as a ssz fixed size byte array of length n. Unlike the lock's, b must be exactly n bytes
// long: no field here may be empty.
func putBytesN(h sszutils.HashWalker, b []byte, n int, field string) error {
	if len(b) != n {
		return errors.New("invalid fixed size bytes length", z.Str("field", field), z.Int("expect", n), z.Int("actual", len(b)))
	}

	h.PutBytes(b)

	return nil
}

// putUint64String appends a uint64 the JSON carries as a canonical decimal string; "007" is refused, it would
// otherwise hash as "7".
func putUint64String(h sszutils.HashWalker, s, field string) error {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(v, 10) != s {
		return errors.New("not a canonical decimal number", z.Str("field", field), z.Str("value", s))
	}

	h.PutUint64(v)

	return nil
}

// from0xHex decodes 0x hex of exactly n bytes, in either case.
func from0xHex(s string, n int, field string) ([]byte, error) {
	hexStr, ok := strings.CutPrefix(s, "0x")

	b, err := hex.DecodeString(hexStr)
	if !ok || err != nil || len(b) != n {
		return nil, errors.New("invalid 0x hex", z.Str("field", field), z.Int("expect", n))
	}

	return b, nil
}
