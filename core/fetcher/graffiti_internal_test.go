// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package fetcher

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

// randomString returns a random string of length n.
func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)

	return string(b)
}

func TestNewGraffitiBuilder(t *testing.T) {
	pubkeys := []core.PubKey{testutil.RandomCorePubKey(t), testutil.RandomCorePubKey(t), testutil.RandomCorePubKey(t)}

	t.Run("graffiti length greater than pubkeys", func(t *testing.T) {
		builder, err := NewGraffitiBuilder(pubkeys, []string{randomString(10), randomString(15), randomString(20), randomString(25)}, false)
		require.Nil(t, builder)
		require.Error(t, err)
	})

	t.Run("graffiti length lesser than pubkeys", func(t *testing.T) {
		builder, err := NewGraffitiBuilder(pubkeys, []string{randomString(10), randomString(15)}, false)
		require.Nil(t, builder)
		require.Error(t, err)
	})

	t.Run("graffiti length greater than 32 characters", func(t *testing.T) {
		builder, err := NewGraffitiBuilder(pubkeys, []string{randomString(33)}, false)
		require.Nil(t, builder)
		require.Error(t, err)
	})

	t.Run("default graffiti", func(t *testing.T) {
		defaultGraffiti := defaultGraffiti()

		var graffitiBytes [32]byte
		commitSHA, _ := version.GitCommit()
		copy(graffitiBytes[:], fmt.Sprintf("charon/%v-%s", version.Version, commitSHA))

		require.Equal(t, graffitiBytes, defaultGraffiti)
	})

	t.Run("get graffiti", func(t *testing.T) {
		graffiti := [][32]byte{{1}, {2}}

		builder := &GraffitiBuilder{
			defaultGraffiti: defaultGraffiti(),
			graffiti: map[core.PubKey][32]byte{
				pubkeys[0]: graffiti[0],
				pubkeys[1]: graffiti[1],
			},
		}

		require.Equal(t, graffiti[0], builder.GetGraffiti(pubkeys[0]))
		require.Equal(t, graffiti[1], builder.GetGraffiti(pubkeys[1]))
		require.Equal(t, defaultGraffiti(), builder.GetGraffiti(testutil.RandomCorePubKey(t)))
	})

	t.Run("nil graffiti", func(t *testing.T) {
		builder, err := NewGraffitiBuilder(pubkeys, nil, false)
		require.NoError(t, err)

		for _, pubkey := range pubkeys {
			require.Equal(t, defaultGraffiti(), builder.GetGraffiti(pubkey))
		}
	})

	t.Run("single graffiti with space for signature", func(t *testing.T) {
		graffiti := randomString(32 - len(obolSignature))
		builder, err := NewGraffitiBuilder(pubkeys, []string{graffiti}, false)
		require.NoError(t, err)

		for _, pubkey := range pubkeys {
			var expected [32]byte
			copy(expected[:], graffiti+obolSignature)

			require.Equal(t, expected, builder.GetGraffiti(pubkey))
		}
	})

	t.Run("single graffiti without space for signature", func(t *testing.T) {
		graffiti := randomString(32 - len(obolSignature) + 1)
		builder, err := NewGraffitiBuilder(pubkeys, []string{graffiti}, false)
		require.NoError(t, err)

		for _, pubkey := range pubkeys {
			var expected [32]byte
			copy(expected[:], graffiti)

			require.Equal(t, expected, builder.GetGraffiti(pubkey))
		}
	})

	t.Run("multiple graffiti", func(t *testing.T) {
		graffiti := []string{randomString(10), randomString(32 - len(obolSignature)), randomString(32 - len(obolSignature) + 1)}
		expectedGraffiti := []string{graffiti[0] + obolSignature, graffiti[1] + obolSignature, graffiti[2]}
		builder, err := NewGraffitiBuilder(pubkeys, graffiti, false)
		require.NoError(t, err)

		for idx, pubkey := range pubkeys {
			var expected [32]byte
			copy(expected[:], expectedGraffiti[idx])

			require.Equal(t, expected, builder.GetGraffiti(pubkey))
		}
	})
}
