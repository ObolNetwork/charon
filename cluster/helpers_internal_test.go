// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	ssz "github.com/ferranbt/fastssz"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/testutil"
)

// hashRootOf calls fn on a fresh ssz.HashWalker and returns the HashRoot as a hex string.
func hashRootOf(t *testing.T, fn func(ssz.HashWalker) error) string {
	t.Helper()

	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)

	require.NoError(t, fn(hh))

	h, err := hh.HashRoot()
	require.NoError(t, err)

	return hex.EncodeToString(h[:])
}

// hashRootWithPrefix simulates the real usage pattern: open an index, call setup to
// write a prior field, then call fn to append the field under test, merkleize, and
// return the HashRoot. This mirrors how these helpers are called inside hashDefinition*.
func hashRootWithPrefix(t *testing.T, setup func(ssz.HashWalker), fn func(ssz.HashWalker) error) string {
	t.Helper()

	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)

	indx := hh.Index()
	setup(hh)
	require.NoError(t, fn(hh))
	hh.Merkleize(indx)

	h, err := hh.HashRoot()
	require.NoError(t, err)

	return hex.EncodeToString(h[:])
}

func TestPutByteList(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(ssz.HashWalker) // nil = empty walker, non-nil = pre-populated
		b        []byte
		limit    int
		expected string
	}{
		{
			name:     "empty_limit64",
			b:        []byte{},
			limit:    64,
			expected: "7a0501f5957bdf9cb3a8ff4966f02265f968658b7a9c62642cba1165e86642f5",
		},
		{
			name:     "hello_limit256",
			b:        []byte("hello"),
			limit:    256,
			expected: "d714c994fb91ed0c822936ddab0934529ab7816e60dc94027e77a4188e2e4459",
		},
		{
			name:     "32bytes_limit64",
			b:        make([]byte, 32),
			limit:    64,
			expected: "e36306f41e65a19bc26226df4c969ef1ae6ac2e29edf4038761d553854385723",
		},
		{
			name:     "all0xff_limit32",
			b:        []byte{0xff, 0xff, 0xff, 0xff},
			limit:    32,
			expected: "a729ed14d00c6e5f58c31993077a42444a53cc9bed4cbf64e43afd4c29a38880",
		},
		{
			name:     "after_uint64_42",
			setup:    func(hh ssz.HashWalker) { hh.PutUint64(42) },
			b:        []byte("hello"),
			limit:    256,
			expected: "bbc79cd2fdb2cc4810be1c265d80e601221f69df244a956b222db5454dd7d439",
		},
		{
			name:     "after_bytes4",
			setup:    func(hh ssz.HashWalker) { hh.PutBytes([]byte{0x01, 0x02, 0x03, 0x04}) },
			b:        []byte{0xff},
			limit:    32,
			expected: "e27cef6249214493f3e7ade1aa0af8130029eedfc7c17d928ed8af341a5511e9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := func(hh ssz.HashWalker) error { return putByteList(hh, tt.b, tt.limit, "field") }

			var got string
			if tt.setup != nil {
				got = hashRootWithPrefix(t, tt.setup, fn)
			} else {
				got = hashRootOf(t, fn)
			}

			require.Equal(t, tt.expected, got)
		})
	}
}

func TestPutBytesN(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(ssz.HashWalker) // nil = empty walker, non-nil = pre-populated
		b        []byte
		n        int
		expected string
	}{
		{
			name:     "nil_n32",
			b:        nil,
			n:        32,
			expected: "0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:     "nil_n20",
			b:        nil,
			n:        20,
			expected: "0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:     "4bytes_n4",
			b:        []byte{0x01, 0x02, 0x03, 0x04},
			n:        4,
			expected: "0102030400000000000000000000000000000000000000000000000000000000",
		},
		{
			name:     "short_n32",
			b:        []byte{0xab, 0xcd},
			n:        32,
			expected: "000000000000000000000000000000000000000000000000000000000000abcd",
		},
		{
			name:     "full_n4",
			b:        []byte{0xde, 0xad, 0xbe, 0xef},
			n:        4,
			expected: "deadbeef00000000000000000000000000000000000000000000000000000000",
		},
		{
			name:     "after_uint64_1",
			setup:    func(hh ssz.HashWalker) { hh.PutUint64(1) },
			b:        []byte{0xab, 0xcd},
			n:        32,
			expected: "392b769bc14dd0593bbb9d28f2fa7c4ec6eb113ef750db4046b7136c5844c95d",
		},
		{
			name:     "after_bytes20",
			setup:    func(hh ssz.HashWalker) { hh.PutBytes(make([]byte, 20)) },
			b:        []byte{0x01, 0x02, 0x03, 0x04},
			n:        4,
			expected: "c092c674a087720f7136046e41d587e355a5f359b3940336f8e4e9dde2ffe236",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := func(hh ssz.HashWalker) error { return putBytesN(hh, tt.b, tt.n) }

			var got string
			if tt.setup != nil {
				got = hashRootWithPrefix(t, tt.setup, fn)
			} else {
				got = hashRootOf(t, fn)
			}

			require.Equal(t, tt.expected, got)
		})
	}
}

func TestPutHexBytes20(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(ssz.HashWalker) // nil = empty walker, non-nil = pre-populated
		addr     string
		expected string
	}{
		{
			name:     "zero_addr",
			addr:     "0x0000000000000000000000000000000000000000",
			expected: "0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:     "all_ones",
			addr:     "0x1111111111111111111111111111111111111111",
			expected: "1111111111111111111111111111111111111111000000000000000000000000",
		},
		{
			name:     "mixed",
			addr:     "0xabcdef0123456789abcdef0123456789abcdef01",
			expected: "abcdef0123456789abcdef0123456789abcdef01000000000000000000000000",
		},
		{
			name:     "after_uint64_99",
			setup:    func(hh ssz.HashWalker) { hh.PutUint64(99) },
			addr:     "0x1111111111111111111111111111111111111111",
			expected: "2051384e282f804390dac5c19fcfd1e4cacca29abacb0f07cd6c17995388f5b0",
		},
		{
			name: "after_bytelist",
			setup: func(hh ssz.HashWalker) {
				_ = putByteList(hh, []byte("prefix"), 256, "f")
			},
			addr:     "0xabcdef0123456789abcdef0123456789abcdef01",
			expected: "c3105b794bd2b28cc863326f5ffa8baad9e1c1d7d424556e188961ca59f69100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := func(hh ssz.HashWalker) error { return putHexBytes20(hh, tt.addr) }

			var got string
			if tt.setup != nil {
				got = hashRootWithPrefix(t, tt.setup, fn)
			} else {
				got = hashRootOf(t, fn)
			}

			require.Equal(t, tt.expected, got)
		})
	}
}

func TestLeftPad(t *testing.T) {
	b := []byte{0x01, 0x02}
	require.Equal(t, []byte{0x01, 0x02}, leftPad(b, 1))
	require.Equal(t, []byte{0x01, 0x02}, leftPad(b, 2))
	require.Equal(t, []byte{0x00, 0x01, 0x02}, leftPad(b, 3))
	require.Equal(t, []byte{0x00, 0x00, 0x01, 0x02}, leftPad(b, 4))
}

func TestVerifySig(t *testing.T) {
	secret, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	addr := eth2util.PublicKeyToAddress(secret.PubKey())
	digest := testutil.RandomRoot()
	sig, err := k1util.Sign(secret, digest[:])
	require.NoError(t, err)

	t.Run("valid signature", func(t *testing.T) {
		ok, err := verifySig(addr, digest[:], sig)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("invalid signature length", func(t *testing.T) {
		var invalidSig [70]byte

		ok, err := verifySig(addr, digest[:], invalidSig[:])
		require.Error(t, err)
		require.ErrorContains(t, err, "signature not 65 bytes")
		require.False(t, ok)
	})

	t.Run("invalid recovery id", func(t *testing.T) {
		var newSig [65]byte
		copy(newSig[:], sig)
		newSig[64] = byte(165) // Make the last byte invalid.

		ok, err := verifySig(addr, digest[:], newSig[:])
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid recovery id")
		require.False(t, ok)
	})

	t.Run("sig ending with 27/28", func(t *testing.T) {
		var newSig [65]byte
		copy(newSig[:], sig)
		newSig[64] += 27 // Make last byte 27/28.

		ok, err := verifySig(addr, digest[:], newSig[:])
		require.NoError(t, err)
		require.True(t, ok)
	})
}

func TestFetchDefinition(t *testing.T) {
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := NewForT(t, 1, 2, 3, seed, random)
	validDef := lock.Definition
	invalidDef := Definition{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimSpace(r.URL.Path) {
		case "/validDef":
			b, _ := validDef.MarshalJSON()
			_, _ = w.Write(b)
		case "/invalidDef":
			b, _ := invalidDef.MarshalJSON()
			_, _ = w.Write(b)
		case "/nonok":
			w.WriteHeader(http.StatusInternalServerError)
		case "/tooLarge":
			// Simulate a response that exceeds maxDefinitionSize (16MB)
			// Write 17MB of data to trigger the size limit
			largeData := make([]byte, 17*1024*1024)
			_, _ = w.Write(largeData)
		}
	}))
	defer server.Close()

	tests := []struct {
		name    string
		url     string
		want    Definition
		wantErr bool
		errMsg  string
	}{
		{
			name:    "Fetch valid definition",
			url:     fmt.Sprintf("%s/%s", server.URL, "validDef"),
			want:    validDef,
			wantErr: false,
		},
		{
			name:    "Fetch invalid definition",
			url:     fmt.Sprintf("%s/%s", server.URL, "invalidDef"),
			want:    invalidDef,
			wantErr: true,
		},
		{
			name:    "HTTP status is not in the 200 range",
			url:     fmt.Sprintf("%s/%s", server.URL, "nonok"),
			want:    invalidDef,
			wantErr: true,
		},
		{
			name:    "Definition file too large (memory exhaustion protection)",
			url:     fmt.Sprintf("%s/%s", server.URL, "tooLarge"),
			want:    invalidDef,
			wantErr: true,
			errMsg:  "definition file too large",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FetchDefinition(context.Background(), tt.url)
			if tt.wantErr {
				require.Error(t, err)

				if tt.errMsg != "" {
					require.ErrorContains(t, err, tt.errMsg)
				}

				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestCreateValidatorKeysDir(t *testing.T) {
	tmp := t.TempDir()

	// First attempt must succeed.
	dir, err := CreateValidatorKeysDir(tmp)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(dir, tmp))
	require.True(t, strings.HasSuffix(dir, "validator_keys"))

	// Second attempt shall succeed as long as the dir is empty.
	dir, err = CreateValidatorKeysDir(tmp)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(dir, tmp))
	require.True(t, strings.HasSuffix(dir, "validator_keys"))

	// Create a file in the directory to make it non-empty.
	err = os.WriteFile(path.Join(dir, "file"), []byte("data"), 0o644)
	require.NoError(t, err)
	_, err = CreateValidatorKeysDir(tmp)
	require.ErrorContains(t, err, "non-empty directory")

	t.Run("mkdir error", func(t *testing.T) {
		// Parent directory does not exist
		_, err := CreateValidatorKeysDir(path.Join(tmp, "nonexistent"))
		require.ErrorContains(t, err, "mkdir")
	})
}

func TestUUID(t *testing.T) {
	t.Run("generate", func(t *testing.T) {
		uuidStr, err := generateUUID(crand.Reader)
		require.NoError(t, err)
		u, err := uuid.Parse(uuidStr)
		require.NoError(t, err)
		require.Equal(t, u.Variant(), uuid.RFC4122)
	})
}
