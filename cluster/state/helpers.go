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

// verifyK1SignedMutation verifies that the signed mutation is signed by a k1 key.
//
//nolint:unused // Will be used in next PR.
func verifyK1SignedMutation(signed SignedMutation) error {
	pubkey, err := k1.ParsePubKey(signed.Signer)
	if err != nil {
		return errors.Wrap(err, "parse signer pubkey")
	}

	hash, err := hashRoot(signed.Mutation)
	if err != nil {
		return errors.Wrap(err, "hash mutation")
	}

	if signed.Hash != hash {
		return errors.New("signed mutation hash mismatch")
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
