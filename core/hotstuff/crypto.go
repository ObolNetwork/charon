// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import (
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
)

func Hash(t MsgType, view View, value string) ([32]byte, error) {
	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)

	index := hh.Index()
	hh.PutUint64(uint64(t))
	hh.PutUint64(uint64(view))
	hh.PutBytes([]byte(value))
	hh.Merkleize(index)

	hash, err := hh.HashRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash root")
	}

	return hash, nil
}

func Sign(privKey *k1.PrivateKey, t MsgType, view View, value string) ([]byte, error) {
	hash, err := Hash(t, view, value)
	if err != nil {
		return nil, err
	}

	sig, err := k1util.Sign(privKey, hash[:])
	if err != nil {
		return nil, errors.Wrap(err, "sign")
	}

	return sig, nil
}
