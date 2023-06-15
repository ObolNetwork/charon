// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	pbv1 "github.com/obolnetwork/charon/cluster/statepb/v1"
)

// nowFunc is the time.Now function aliased for testing.
var nowFunc = timestamppb.Now

// SetNowFuncForT sets the time.Now function for the duration of the test.
func SetNowFuncForT(t *testing.T, f func() *timestamppb.Timestamp) {
	t.Helper()
	cached := nowFunc
	t.Cleanup(func() {
		nowFunc = cached
	})

	nowFunc = f
}

// hashSignedMutation returns the hash of a signed mutation.
func hashSignedMutation(signed *pbv1.SignedMutation) ([32]byte, error) {
	if signed.Mutation == nil {
		return [32]byte{}, errors.New("invalid signed mutation")
	}

	h := sha256.New()

	// Field 0: Mutation
	b, err := hashMutation(signed.Mutation)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash mutation")
	}

	if _, err := h.Write(b[:]); err != nil {
		return [32]byte{}, errors.Wrap(err, "hash mutation")
	}

	// Field 1: Signer
	if _, err := h.Write(signed.Signer); err != nil {
		return [32]byte{}, errors.Wrap(err, "hash signer")
	}

	// Field 2: Signature
	if _, err := h.Write(signed.Signature); err != nil {
		return [32]byte{}, errors.Wrap(err, "hash signature")
	}

	return [32]byte(h.Sum(nil)), nil
}

// hashMutation returns the hash of a mutation.
func hashMutation(m *pbv1.Mutation) ([32]byte, error) {
	if m.Timestamp == nil || m.Data == nil {
		return [32]byte{}, errors.New("invalid mutation")
	}

	h := sha256.New()

	// Field 0: Parent
	if _, err := h.Write(m.Parent); err != nil {
		return [32]byte{}, errors.Wrap(err, "hash parent")
	}

	// Field 1: Type
	if _, err := h.Write([]byte(m.Type)); err != nil {
		return [32]byte{}, errors.Wrap(err, "hash type")
	}

	// Field 2: Timestamp
	if _, err := h.Write(int64ToBytes(m.Timestamp.Seconds)); err != nil {
		return [32]byte{}, errors.Wrap(err, "hash timestamp seconds")
	}

	if _, err := h.Write(int32ToBytes(m.Timestamp.Nanos)); err != nil {
		return [32]byte{}, errors.Wrap(err, "hash timestamp nanos")
	}

	// Field 3: Data
	if _, err := h.Write([]byte(m.Data.TypeUrl)); err != nil {
		return [32]byte{}, errors.Wrap(err, "hash data type url")
	}

	if _, err := h.Write(m.Data.Value); err != nil {
		return [32]byte{}, errors.Wrap(err, "hash data value")
	}

	return [32]byte(h.Sum(nil)), nil
}

func int64ToBytes(i int64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(i))

	return b
}

func int32ToBytes(i int32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(i))

	return b
}

// verifyEmptySig verifies that the signed mutation isn't signed.
func verifyEmptySig(signed *pbv1.SignedMutation) error {
	if len(signed.Signature) != 0 {
		return errors.New("non-empty signature")
	}

	if len(signed.Signer) != 0 {
		return errors.New("non-empty signer")
	}

	return nil
}

// SignK1 signs the mutation with the provided k1 secret.
func SignK1(m *pbv1.Mutation, secret *k1.PrivateKey) (*pbv1.SignedMutation, error) {
	hash, err := hashMutation(m)
	if err != nil {
		return nil, errors.Wrap(err, "hash mutation")
	}

	sig, err := k1util.Sign(secret, hash[:])
	if err != nil {
		return nil, errors.Wrap(err, "sign mutation")
	}

	return &pbv1.SignedMutation{
		Mutation:  m,
		Signer:    secret.PubKey().SerializeCompressed(),
		Signature: sig[:64], // Strip recovery id
	}, nil
}

// verifyK1SignedMutation verifies that the signed mutation is signed by a k1 key.
//
// TODO(corver): Figure out no-verify case.
func verifyK1SignedMutation(signed *pbv1.SignedMutation) error {
	pubkey, err := k1.ParsePubKey(signed.Signer)
	if err != nil {
		return errors.Wrap(err, "parse signer pubkey")
	}

	hash, err := hashMutation(signed.Mutation)
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

// ValidatorToProto converts a legacy cluster validator to a protobuf validator.
func ValidatorToProto(val cluster.DistValidator, addrs cluster.ValidatorAddresses) (*pbv1.Validator, error) {
	var regJSON []byte
	if !val.ZeroRegistration() {
		reg, err := val.Eth2Registration()
		if err != nil {
			return nil, errors.Wrap(err, "eth2 builder registration")
		}

		regJSON, err = json.Marshal(reg)
		if err != nil {
			return nil, errors.Wrap(err, "marshal builder registration")
		}
	}

	return &pbv1.Validator{
		PublicKey:               val.PubKey,
		PubShares:               val.PubShares,
		FeeRecipientAddress:     addrs.FeeRecipientAddress,
		WithdrawalAddress:       addrs.WithdrawalAddress,
		BuilderRegistrationJson: regJSON,
	}, nil
}
