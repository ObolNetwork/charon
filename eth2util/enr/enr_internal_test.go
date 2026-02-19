// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package enr

import (
	"crypto/ecdsa"
	"encoding/base64"
	"math/rand"
	"testing"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

func TestBackwardsENR(t *testing.T) {
	random := rand.New(rand.NewSource(time.Now().Unix()))
	for range 100 {
		k, err := ecdsa.GenerateKey(k1.S256(), random)
		require.NoError(t, err)

		//nolint:staticcheck // We are using it in tests in a safely manner in testing.
		// We expect a bit more utility functions to be implemented in the k1 package in the future
		// This is currently the only way to get deterministic keys for testing.
		key := k1.PrivKeyFromBytes(k.D.Bytes())

		record, err := New(key)
		require.NoError(t, err)

		// Encode ENR string with padding which is supported by charon versions v0.9.0 or earlier.
		enrStr := "enr:" + base64.URLEncoding.EncodeToString(encodeElements(record.Signature, record.kvs))

		_, err = Parse(enrStr)
		require.NoError(t, err)
	}
}
