// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package manifest

import (
	"crypto/sha256"
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
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
)

// hashLen is the length of a hash.
const hashLen = 32

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
func hashSignedMutation(signed *manifestpb.SignedMutation) ([]byte, error) {
	if signed.Mutation == nil {
		return nil, errors.New("invalid signed mutation")
	}

	h := sha256.New()

	// Field 0: Mutation
	b, err := hashMutation(signed.Mutation)
	if err != nil {
		return nil, errors.Wrap(err, "hash mutation")
	}

	if _, err := h.Write(b); err != nil {
		return nil, errors.Wrap(err, "hash mutation")
	}

	// Field 1: Signer
	if _, err := h.Write(signed.Signer); err != nil {
		return nil, errors.Wrap(err, "hash signer")
	}

	// Field 2: Signature
	if _, err := h.Write(signed.Signature); err != nil {
		return nil, errors.Wrap(err, "hash signature")
	}

	return h.Sum(nil), nil
}

// hashMutation returns the hash of a mutation.
func hashMutation(m *manifestpb.Mutation) ([]byte, error) {
	if m.Data == nil {
		return nil, errors.New("invalid mutation")
	}

	h := sha256.New()

	// Field 0: Parent
	if _, err := h.Write(m.Parent); err != nil {
		return nil, errors.Wrap(err, "hash parent")
	}

	// Field 1: Type
	if _, err := h.Write([]byte(m.Type)); err != nil {
		return nil, errors.Wrap(err, "hash type")
	}

	// Field 2: Data
	if _, err := h.Write([]byte(m.Data.TypeUrl)); err != nil {
		return nil, errors.Wrap(err, "hash data type url")
	}

	if _, err := h.Write(m.Data.Value); err != nil {
		return nil, errors.Wrap(err, "hash data value")
	}

	return h.Sum(nil), nil
}

// verifyEmptySig verifies that the signed mutation isn't signed.
func verifyEmptySig(signed *manifestpb.SignedMutation) error {
	if len(signed.Signature) != 0 {
		return errors.New("non-empty signature")
	}

	if len(signed.Signer) != 0 {
		return errors.New("non-empty signer")
	}

	return nil
}

// SignK1 signs the mutation with the provided k1 secret.
func SignK1(m *manifestpb.Mutation, secret *k1.PrivateKey) (*manifestpb.SignedMutation, error) {
	hash, err := hashMutation(m)
	if err != nil {
		return nil, errors.Wrap(err, "hash mutation")
	}

	sig, err := k1util.Sign(secret, hash)
	if err != nil {
		return nil, errors.Wrap(err, "sign mutation")
	}

	return &manifestpb.SignedMutation{
		Mutation:  m,
		Signer:    secret.PubKey().SerializeCompressed(),
		Signature: sig,
	}, nil
}

// verifyK1SignedMutation verifies that the signed mutation is signed by a k1 key.
func verifyK1SignedMutation(signed *manifestpb.SignedMutation) error {
	pubkey, err := k1.ParsePubKey(signed.Signer)
	if err != nil {
		return errors.Wrap(err, "parse signer pubkey")
	}

	hash, err := hashMutation(signed.Mutation)
	if err != nil {
		return errors.Wrap(err, "hash mutation")
	}

	if ok, err := k1util.Verify65(pubkey, hash, signed.Signature); err != nil {
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
func ValidatorToProto(val cluster.DistValidator, addrs cluster.ValidatorAddresses) (*manifestpb.Validator, error) {
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

	return &manifestpb.Validator{
		PublicKey:               val.PubKey,
		PubShares:               val.PubShares,
		FeeRecipientAddress:     addrs.FeeRecipientAddress,
		WithdrawalAddress:       addrs.WithdrawalAddress,
		BuilderRegistrationJson: regJSON,
	}, nil
}
