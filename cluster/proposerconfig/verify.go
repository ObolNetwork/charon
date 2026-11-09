// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package proposerconfig

import (
	"bytes"
	"slices"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/enr"
)

var (
	// ErrLockHashMismatch is returned when the document belongs to a different cluster lock.
	ErrLockHashMismatch = errors.NewSentinel("proposer config lock hash mismatch")
	// ErrInvalid is returned when the document violates the validity rules.
	ErrInvalid = errors.NewSentinel("proposer config invalid")
)

// invalid returns an error wrapping ErrInvalid with the reason.
func invalid(reason string, fields ...z.Field) error {
	return errors.Wrap(ErrInvalid, reason, fields...)
}

// Verify checks the document against the lock: lock hash, version, stored hash, editable fields and signatures.
// Revision 0 must be unsigned; later revisions need threshold distinct valid operator signatures.
func Verify(doc Document, lock cluster.Lock) error {
	if !bytes.Equal(doc.LockHash, lock.LockHash) {
		return errors.Wrap(ErrLockHashMismatch, "document lock hash differs from lock")
	}

	if doc.Version != Version {
		return invalid("unknown version", z.Str("version", doc.Version))
	}

	hash, err := doc.Hash()
	if err != nil {
		return err
	}

	if len(doc.StoredHash) > 0 && !bytes.Equal(doc.StoredHash, hash[:]) {
		return invalid("content was modified, revision hash mismatch")
	}

	err = checkEditableFields(doc.Config)
	if err != nil {
		return err
	}

	if doc.Revision == 0 {
		if len(doc.Signatures) != 0 {
			return invalid("revision 0 must have no signatures", z.Int("signatures", len(doc.Signatures)))
		}

		return nil
	}

	if len(doc.Signatures) < lock.Threshold {
		return invalid("not enough signatures", z.Int("signatures", len(doc.Signatures)), z.Int("threshold", lock.Threshold))
	}

	seen := make(map[int]bool)

	for _, sig := range doc.Signatures {
		if seen[sig.Operator] {
			return invalid("duplicate operator signature", z.Int("operator", sig.Operator))
		}

		seen[sig.Operator] = true

		err := verifySignature(hash, lock, sig.Operator, sig.Signature)
		if err != nil {
			return err
		}
	}

	return nil
}

// Sign returns the operator's signature of the document's revision hash.
func Sign(doc Document, key *k1.PrivateKey) ([]byte, error) {
	hash, err := doc.Hash()
	if err != nil {
		return nil, err
	}

	sig, err := k1util.Sign(key, hash[:])
	if err != nil {
		return nil, errors.Wrap(err, "sign proposer config")
	}

	return sig, nil
}

// VerifySignature checks that sig is the given operator's signature of the document's revision hash.
func VerifySignature(doc Document, lock cluster.Lock, operator int, sig []byte) error {
	hash, err := doc.Hash()
	if err != nil {
		return err
	}

	return verifySignature(hash, lock, operator, sig)
}

func verifySignature(hash [32]byte, lock cluster.Lock, operator int, sig []byte) error {
	if operator < 0 || operator >= len(lock.Operators) {
		return invalid("operator index out of range", z.Int("operator", operator))
	}

	record, err := enr.Parse(lock.Operators[operator].ENR)
	if err != nil {
		return errors.Wrap(err, "parse operator enr", z.Int("operator", operator))
	}

	ok, err := k1util.Verify65(record.PubKey, hash[:], sig)
	if err != nil {
		return invalid("malformed signature", z.Int("operator", operator))
	}

	if !ok {
		return invalid("signature does not verify", z.Int("operator", operator))
	}

	return nil
}

// checkEditableFields rejects the fields the edit command cannot set: per-validator gas limits and builders, and
// per-builder overrides. The proposer config is only changed through the CLI.
func checkEditableFields(c Config) error {
	for pubkey, s := range c.ProposerConfig {
		if s.GasLimit != "" || s.Builder != nil {
			return invalid("proposer_config entry sets more than fee_recipient", z.Str("pubkey", pubkey))
		}
	}

	if c.DefaultConfig.Builder == nil {
		return nil
	}

	for _, e := range c.DefaultConfig.Builder.Builders {
		if e.MinBid != "" || e.BuilderBoostFactor != "" || e.MaxExecutionPayment != "" {
			return invalid("builder entry sets more than url", z.Str("url", log.RedactURL(e.URL, true)))
		}
	}

	return nil
}

// SignerIndexes returns the operator indexes that signed the document, ascending.
func (d Document) SignerIndexes() []int {
	idxs := make([]int, 0, len(d.Signatures))
	for _, sig := range d.Signatures {
		idxs = append(idxs, sig.Operator)
	}

	slices.Sort(idxs)

	return idxs
}
