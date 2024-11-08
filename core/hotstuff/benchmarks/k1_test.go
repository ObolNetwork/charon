// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package benchmarks_test

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/k1util"
)

func BenchmarkK1(b *testing.B) {
	var (
		tcount                 = 0
		telapsed time.Duration = 0
	)

	for _, test := range tests {
		name := fmt.Sprintf("total=%d, threshold=%d", test.total, test.threshold)
		b.Run(name, func(b *testing.B) {
			for range iterations {
				privKeys := make([]*k1.PrivateKey, 0)
				for range test.total {
					privKey, err := k1.GeneratePrivateKey()
					require.NoError(b, err)
					privKeys = append(privKeys, privKey)
				}

				var hash [32]byte
				_, err := rand.Read(hash[:])
				require.NoError(b, err)

				startedAt := time.Now()

				for _, pk := range privKeys {
					parSig, err := k1util.Sign(pk, hash[:])
					require.NoError(b, err)

					ok, err := k1util.Verify65(pk.PubKey(), hash[:], parSig)
					require.NoError(b, err)
					require.True(b, ok)
				}

				tcount++
				telapsed += time.Since(startedAt)
			}
		})
	}

	telapsed /= time.Duration(tcount)
	b.Logf("Average time: %s", telapsed)
}
