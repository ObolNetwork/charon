// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package proposerconfig

import (
	"math/rand"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
)

func TestVerify(t *testing.T) {
	lock, keys, _ := cluster.NewForT(t, 1, 3, 4, 7, rand.New(rand.NewSource(7)))
	require.Equal(t, 3, lock.Threshold)

	newDoc := func(revision uint64, signers ...int) Document {
		doc := Document{
			Version:  Version,
			LockHash: lock.LockHash,
			Revision: revision,
			Config: Config{
				DefaultConfig:  Settings{FeeRecipient: addrA, GasLimit: "200000000"},
				ProposerConfig: map[string]Settings{},
			},
		}

		for _, idx := range signers {
			sig, err := Sign(doc, keys[idx])
			require.NoError(t, err)

			doc.Signatures = append(doc.Signatures, Signature{Operator: idx, Signature: sig})
		}

		return doc
	}

	other, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	tests := []struct {
		name   string
		doc    func() Document
		errIs  error
		errMsg string
	}{
		{name: "revision 0 no signatures", doc: func() Document { return newDoc(0) }},
		{name: "revision 0 one signature", doc: func() Document { return newDoc(0, 0) }, errIs: ErrInvalid},
		{name: "revision 1 threshold", doc: func() Document { return newDoc(1, 0, 1, 2) }},
		{name: "revision 1 below threshold", doc: func() Document { return newDoc(1, 0, 1) }, errIs: ErrInvalid},
		{name: "revision 1 duplicate operator", doc: func() Document { return newDoc(1, 0, 1, 1) }, errIs: ErrInvalid},
		{
			name: "revision 1 index out of range",
			doc: func() Document {
				doc := newDoc(1, 0, 1, 2)
				doc.Signatures[2].Operator = 9

				return doc
			},
			errIs: ErrInvalid,
		},
		{
			name: "revision 1 negative operator index",
			doc: func() Document {
				doc := newDoc(1, 0, 1, 2)
				doc.Signatures[2].Operator = -1

				return doc
			},
			errIs:  ErrInvalid,
			errMsg: "operator index out of range",
		},
		{
			name: "revision 1 truncated signature",
			doc: func() Document {
				doc := newDoc(1, 0, 1, 2)
				doc.Signatures[2].Signature = doc.Signatures[2].Signature[:64]

				return doc
			},
			errIs:  ErrInvalid,
			errMsg: "malformed signature",
		},
		{
			name: "revision 1 nil signature",
			doc: func() Document {
				doc := newDoc(1, 0, 1, 2)
				doc.Signatures[2].Signature = nil

				return doc
			},
			errIs:  ErrInvalid,
			errMsg: "malformed signature",
		},
		{
			name: "revision 1 signature filed under another operator",
			doc: func() Document {
				doc := newDoc(1, 0, 1, 2)
				doc.Signatures[2].Operator = 3

				return doc
			},
			errIs:  ErrInvalid,
			errMsg: "signature does not verify",
		},
		{
			name: "revision 1 non-operator key",
			doc: func() Document {
				doc := newDoc(1, 0, 1, 2)
				sig, err := Sign(doc, other)
				require.NoError(t, err)

				doc.Signatures[2].Signature = sig

				return doc
			},
			errIs: ErrInvalid,
		},
		{
			name: "stored hash differs",
			doc: func() Document {
				doc := newDoc(0)
				doc.StoredHash = make([]byte, 32)

				return doc
			},
			errIs:  ErrInvalid,
			errMsg: "content was modified",
		},
		{
			name: "stored hash matches",
			doc: func() Document {
				doc := newDoc(0)
				h, err := doc.Hash()
				require.NoError(t, err)

				doc.StoredHash = h[:]

				return doc
			},
		},
		{
			name: "other lock hash",
			doc: func() Document {
				doc := newDoc(0)
				doc.LockHash = make([]byte, 32)

				return doc
			},
			errIs: ErrLockHashMismatch,
		},
		{
			name: "unknown version",
			doc: func() Document {
				doc := newDoc(0)
				doc.Version = "v3.0.0"

				return doc
			},
			errIs: ErrInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Verify(tt.doc(), lock)
			if tt.errIs == nil {
				require.NoError(t, err)
				return
			}

			require.ErrorIs(t, err, tt.errIs)
			require.ErrorContains(t, err, tt.errMsg)
		})
	}
}

func TestSignerIndexes(t *testing.T) {
	doc := Document{Signatures: []Signature{{Operator: 2}, {Operator: 0}}}
	require.Equal(t, []int{0, 2}, doc.SignerIndexes())
	require.Empty(t, Document{}.SignerIndexes())
}
