// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	"bytes"
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
	"github.com/google/uuid"
	"github.com/pk910/dynamic-ssz/hasher"
	"github.com/pk910/dynamic-ssz/sszutils"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth1wrap"
	"github.com/obolnetwork/charon/app/eth1wrap/mocks"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/testutil"
)

// hashRootOf calls fn on a fresh sszutils.HashWalker and returns the HashRoot as a hex string.
func hashRootOf(t *testing.T, fn func(sszutils.HashWalker) error) string {
	t.Helper()

	hh := hasher.DefaultHasherPool.Get()
	defer hasher.DefaultHasherPool.Put(hh)

	require.NoError(t, fn(hh))

	h, err := hh.HashRoot()
	require.NoError(t, err)

	return hex.EncodeToString(h[:])
}

// hashRootWithPrefix simulates the real usage pattern: open an index, call setup to
// write a prior field, then call fn to append the field under test, merkleize, and
// return the HashRoot. This mirrors how these helpers are called inside hashDefinition*.
func hashRootWithPrefix(t *testing.T, setup func(sszutils.HashWalker), fn func(sszutils.HashWalker) error) string {
	t.Helper()

	hh := hasher.DefaultHasherPool.Get()
	defer hasher.DefaultHasherPool.Put(hh)

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
		name  string
		setup func(sszutils.HashWalker) // nil = empty walker, non-nil = pre-populated
		b     []byte
		limit int
	}{
		{
			name:  "empty_limit64",
			b:     []byte{},
			limit: 64,
		},
		{
			name:  "hello_limit256",
			b:     []byte("hello"),
			limit: 256,
		},
		{
			name:  "32bytes_limit64",
			b:     make([]byte, 32),
			limit: 64,
		},
		{
			name:  "all0xff_limit32",
			b:     []byte{0xff, 0xff, 0xff, 0xff},
			limit: 32,
		},
		{
			name:  "after_uint64_42",
			setup: func(hh sszutils.HashWalker) { hh.PutUint64(42) },
			b:     []byte("hello"),
			limit: 256,
		},
		{
			name:  "after_bytes4",
			setup: func(hh sszutils.HashWalker) { hh.PutBytes([]byte{0x01, 0x02, 0x03, 0x04}) },
			b:     []byte{0xff},
			limit: 32,
		},
	}

	roots := make(map[string]string)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := func(hh sszutils.HashWalker) error { return putByteList(hh, tt.b, tt.limit, "field") }

			var got string
			if tt.setup != nil {
				got = hashRootWithPrefix(t, tt.setup, fn)
			} else {
				got = hashRootOf(t, fn)
			}

			roots[tt.name] = got
		})
	}

	testutil.RequireGoldenJSON(t, roots)
}

func TestPutBytesN(t *testing.T) {
	tests := []struct {
		name  string
		setup func(sszutils.HashWalker) // nil = empty walker, non-nil = pre-populated
		b     []byte
		n     int
	}{
		{
			name: "nil_n32",
			b:    nil,
			n:    32,
		},
		{
			name: "nil_n20",
			b:    nil,
			n:    20,
		},
		{
			name: "4bytes_n4",
			b:    []byte{0x01, 0x02, 0x03, 0x04},
			n:    4,
		},
		{
			name: "short_n32",
			b:    []byte{0xab, 0xcd},
			n:    32,
		},
		{
			name: "full_n4",
			b:    []byte{0xde, 0xad, 0xbe, 0xef},
			n:    4,
		},
		{
			name:  "after_uint64_1",
			setup: func(hh sszutils.HashWalker) { hh.PutUint64(1) },
			b:     []byte{0xab, 0xcd},
			n:     32,
		},
		{
			name:  "after_bytes20",
			setup: func(hh sszutils.HashWalker) { hh.PutBytes(make([]byte, 20)) },
			b:     []byte{0x01, 0x02, 0x03, 0x04},
			n:     4,
		},
	}

	roots := make(map[string]string)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := func(hh sszutils.HashWalker) error { return putBytesN(hh, tt.b, tt.n) }

			var got string
			if tt.setup != nil {
				got = hashRootWithPrefix(t, tt.setup, fn)
			} else {
				got = hashRootOf(t, fn)
			}

			roots[tt.name] = got
		})
	}

	testutil.RequireGoldenJSON(t, roots)
}

func TestPutHexBytes20(t *testing.T) {
	tests := []struct {
		name  string
		setup func(sszutils.HashWalker) // nil = empty walker, non-nil = pre-populated
		addr  string
	}{
		{
			name: "zero_addr",
			addr: "0x0000000000000000000000000000000000000000",
		},
		{
			name: "all_ones",
			addr: "0x1111111111111111111111111111111111111111",
		},
		{
			name: "mixed",
			addr: "0xabcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name:  "after_uint64_99",
			setup: func(hh sszutils.HashWalker) { hh.PutUint64(99) },
			addr:  "0x1111111111111111111111111111111111111111",
		},
		{
			name: "after_bytelist",
			setup: func(hh sszutils.HashWalker) {
				_ = putByteList(hh, []byte("prefix"), 256, "f")
			},
			addr: "0xabcdef0123456789abcdef0123456789abcdef01",
		},
	}

	roots := make(map[string]string)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := func(hh sszutils.HashWalker) error { return putHexBytes20(hh, tt.addr) }

			var got string
			if tt.setup != nil {
				got = hashRootWithPrefix(t, tt.setup, fn)
			} else {
				got = hashRootOf(t, fn)
			}

			roots[tt.name] = got
		})
	}

	testutil.RequireGoldenJSON(t, roots)
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

func TestVerifySigOrERC1271(t *testing.T) {
	secret, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	addr := eth2util.PublicKeyToAddress(secret.PubKey())
	digest := testutil.RandomRoot()

	eoaSig, err := k1util.Sign(secret, digest[:])
	require.NoError(t, err)

	// A Safe multisig signature is concatenated 65-byte signatures (threshold=2 here), opaque to the mock.
	multisig := bytes.Repeat([]byte{0x42}, 2*sszLenK1Sig)

	t.Run("valid EOA does not consult ERC-1271", func(t *testing.T) {
		eth1 := mocks.NewEthClientRunner(t) // No expectations: panics if VerifySmartContractBasedSignature is called.

		ok, err := verifySigOrERC1271(eth1, addr, digest[:], eoaSig)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("multisig routes to ERC-1271 valid", func(t *testing.T) {
		eth1 := mocks.NewEthClientRunner(t)
		eth1.On("VerifySmartContractBasedSignature", addr, [32]byte(digest), multisig).Return(true, nil).Once()

		ok, err := verifySigOrERC1271(eth1, addr, digest[:], multisig)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("multisig ERC-1271 invalid", func(t *testing.T) {
		eth1 := mocks.NewEthClientRunner(t)
		eth1.On("VerifySmartContractBasedSignature", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Once()

		ok, err := verifySigOrERC1271(eth1, addr, digest[:], multisig)
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("multisig ERC-1271 error propagates", func(t *testing.T) {
		eth1 := mocks.NewEthClientRunner(t)
		eth1.On("VerifySmartContractBasedSignature", mock.Anything, mock.Anything, mock.Anything).
			Return(false, errors.New("rpc down")).Once()

		_, err := verifySigOrERC1271(eth1, addr, digest[:], multisig)
		require.ErrorContains(t, err, "rpc down")
	})

	t.Run("65-byte non-matching EOA falls through to ERC-1271", func(t *testing.T) {
		other, err := k1.GeneratePrivateKey()
		require.NoError(t, err)

		wrongSig, err := k1util.Sign(other, digest[:]) // Valid 65-byte sig, but recovers to a different address.
		require.NoError(t, err)

		eth1 := mocks.NewEthClientRunner(t)
		eth1.On("VerifySmartContractBasedSignature", addr, [32]byte(digest), wrongSig).Return(true, nil).Once()

		ok, err := verifySigOrERC1271(eth1, addr, digest[:], wrongSig)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("65-byte unrecoverable EOA falls through to ERC-1271", func(t *testing.T) {
		// A single 65-byte Safe signature whose v-byte is not a valid EOA recovery id: verifySig
		// errors, but it must still be offered to the ERC-1271 contract rather than rejected outright.
		bad := make([]byte, sszLenK1Sig)
		bad[64] = 200 // Invalid EOA recovery id.

		eth1 := mocks.NewEthClientRunner(t)
		eth1.On("VerifySmartContractBasedSignature", addr, [32]byte(digest), bad).Return(true, nil).Once()

		ok, err := verifySigOrERC1271(eth1, addr, digest[:], bad)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("nil eth1 client does not panic", func(t *testing.T) {
		// A failing EOA signature with no eth1 client cannot be checked via ERC-1271; it must
		// report not-verified rather than panic.
		ok, err := verifySigOrERC1271(nil, addr, digest[:], make([]byte, 2*sszLenK1Sig))
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("no eth1 endpoint reports EOA result not client error", func(t *testing.T) {
		// A regular signer never configures an execution client. A failing EOA signature must report
		// the plain verification result, not the (irrelevant) "endpoint not set" client error.
		other, err := k1.GeneratePrivateKey()
		require.NoError(t, err)

		wrongSig, err := k1util.Sign(other, digest[:]) // Valid 65-byte sig recovering to a different address.
		require.NoError(t, err)

		eth1 := mocks.NewEthClientRunner(t)
		eth1.On("VerifySmartContractBasedSignature", mock.Anything, mock.Anything, mock.Anything).
			Return(false, eth1wrap.ErrNoExecutionEngineAddr).Once()

		ok, err := verifySigOrERC1271(eth1, addr, digest[:], wrongSig)
		require.NoError(t, err) // EOA mismatch (no error), not the client error.
		require.False(t, ok)
	})
}

func TestValidateSignatureLength(t *testing.T) {
	tests := []struct {
		name    string
		version string
		length  int
		wantErr string
	}{
		// v1.11+ allows a single signature or concatenated Safe multisig signatures (multiple of 65).
		{name: "v1.11 empty", version: v1_11, length: 0},
		{name: "v1.11 single eoa", version: v1_11, length: sszLenK1Sig},
		{name: "v1.11 safe threshold 2", version: v1_11, length: 2 * sszLenK1Sig},
		{name: "v1.11 safe threshold 3", version: v1_11, length: 3 * sszLenK1Sig},
		{name: "v1.11 max", version: v1_11, length: sszMaxK1Sigs * sszLenK1Sig},
		{name: "v1.11 not multiple of 65", version: v1_11, length: 100, wantErr: "multiple of 65 bytes"},
		{name: "v1.11 exceeds maximum", version: v1_11, length: (sszMaxK1Sigs + 1) * sszLenK1Sig, wantErr: "exceeds maximum length"},
		// Pre-v1.11 only allows a single fixed 65-byte signature (or empty); multisig is rejected.
		{name: "v1.10 empty", version: v1_10, length: 0},
		{name: "v1.10 single eoa", version: v1_10, length: sszLenK1Sig},
		{name: "v1.10 multisig rejected", version: v1_10, length: 2 * sszLenK1Sig, wantErr: "signature must be 65 bytes"},
		{name: "v1.10 not 65 rejected", version: v1_10, length: 100, wantErr: "signature must be 65 bytes"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSignatureLength(tt.version, make([]byte, tt.length), "test signature")
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
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
