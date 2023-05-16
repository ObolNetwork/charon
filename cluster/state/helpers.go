// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/z"
)

// nowFunc is the time.Now function aliased for testing.
var nowFunc = time.Now

// SetNowFuncForT sets the time.Now function for the duration of the test.
func SetNowFuncForT(t *testing.T, f func() time.Time) {
	t.Helper()
	cached := nowFunc
	t.Cleanup(func() {
		nowFunc = cached
	})

	nowFunc = f
}

// hashRoot hashes a ssz root hasher object.
func hashRoot(hasher rootHasher) ([32]byte, error) {
	hw := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hw)

	if err := hasher.HashTreeRootWith(hw); err != nil {
		return [32]byte{}, errors.Wrap(err, "hash tree root")
	}

	resp, err := hw.HashRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash root")
	}

	return resp, nil
}

// verifyEmptySig verifies that the signed mutation isn't signed.
func verifyEmptySig(signed SignedMutation) error {
	if len(signed.Signature) != 0 {
		return errors.New("non-empty signature")
	}

	if len(signed.Signer) != 0 {
		return errors.New("non-empty signer")
	}

	return nil
}

// SignK1 signs the mutation with the provided k1 secret.
func SignK1(m Mutation, secret *k1.PrivateKey) (SignedMutation, error) {
	hash, err := hashRoot(m)
	if err != nil {
		return SignedMutation{}, errors.Wrap(err, "hash mutation")
	}

	sig, err := k1util.Sign(secret, hash[:])
	if err != nil {
		return SignedMutation{}, errors.Wrap(err, "sign mutation")
	}

	return SignedMutation{
		Mutation:  m,
		Signer:    secret.PubKey().SerializeCompressed(),
		Signature: sig[:64], // Strip recovery id
	}, nil
}

// verifyK1SignedMutation verifies that the signed mutation is signed by a k1 key.
//
// TODO(corver): Figure out no-verify case.
func verifyK1SignedMutation(signed SignedMutation) error {
	pubkey, err := k1.ParsePubKey(signed.Signer)
	if err != nil {
		return errors.Wrap(err, "parse signer pubkey")
	}

	hash, err := hashRoot(signed.Mutation)
	if err != nil {
		return errors.Wrap(err, "hash mutation")
	}

	if ok, err := k1util.Verify(pubkey, hash[:], signed.Signature); err != nil {
		return errors.Wrap(err, "verify signature")
	} else if !ok {
		return errors.New("invalid mutation signature")
	}

	return nil
}

// ethHex represents a byte slice that is json formatted as 0x prefixed hex.
type ethHex []byte

func (h *ethHex) UnmarshalJSON(data []byte) error {
	var strHex string
	if err := json.Unmarshal(data, &strHex); err != nil {
		return errors.Wrap(err, "unmarshal hex string")
	}

	resp, err := hex.DecodeString(strings.TrimPrefix(strHex, "0x"))
	if err != nil {
		return errors.Wrap(err, "unmarshal hex")
	}

	*h = resp

	return nil
}

func (h ethHex) MarshalJSON() ([]byte, error) {
	resp, err := json.Marshal(to0xHex(h))
	if err != nil {
		return nil, errors.Wrap(err, "marshal hex")
	}

	return resp, nil
}

// to0xHex returns the bytes as a 0x prefixed hex string.
func to0xHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}

	return fmt.Sprintf("%#x", b)
}

// to0xHex returns bytes represented by the hex string.
func from0xHex(s string, length int) ([]byte, error) {
	if s == "" {
		return nil, nil
	}

	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return nil, errors.Wrap(err, "decode hex")
	} else if len(b) != length {
		return nil, errors.Wrap(err, "invalid hex length", z.Int("expect", length), z.Int("actual", len(b)))
	}

	return b, nil
}

var _ MutationData = emptyData{}

// emptyData is a empty MutationData implementation.
type emptyData struct{}

func (emptyData) HashTreeRootWith(ssz.HashWalker) error {
	return nil
}

func (emptyData) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(struct{}{})
	if err != nil {
		return nil, errors.Wrap(err, "marshal empty data")
	}

	return b, nil
}
