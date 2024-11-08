// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package benchmarks_test

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/tbls"
)

func BenchmarkTBLS(b *testing.B) {
	var (
		tcount                 = 0
		telapsed time.Duration = 0
	)

	for _, test := range tests {
		name := fmt.Sprintf("total=%d, threshold=%d", test.total, test.threshold)
		b.Run(name, func(b *testing.B) {
			for range iterations {
				privKey, err := tbls.GenerateSecretKey()
				require.NoError(b, err)

				pubKey, err := tbls.SecretToPublicKey(privKey)
				require.NoError(b, err)

				privKeysMap, err := tbls.ThresholdSplit(privKey, test.total, test.threshold)
				require.NoError(b, err)

				var hash [32]byte
				_, err = rand.Read(hash[:])
				require.NoError(b, err)

				startedAt := time.Now()

				parSigs := make(map[int]tbls.Signature, test.threshold)
				for i, pk := range privKeysMap {
					parSig, err := tbls.Sign(pk, hash[:])
					require.NoError(b, err)
					parSigs[i] = parSig
				}

				aggSig, err := tbls.ThresholdAggregate(parSigs)
				require.NoError(b, err)

				err = tbls.Verify(pubKey, hash[:], aggSig)
				require.NoError(b, err)

				tcount++
				telapsed += time.Since(startedAt)
			}
		})
	}

	telapsed /= time.Duration(tcount)
	b.Logf("Average time: %s", telapsed)
}
