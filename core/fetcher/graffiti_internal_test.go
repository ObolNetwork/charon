// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package fetcher

import (
	"crypto/rand"
	"fmt"
	"reflect"
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

func TestGetGraffitiFunc(t *testing.T) {
	pubkeys := []core.PubKey{testutil.RandomCorePubKey(t), testutil.RandomCorePubKey(t)}

	t.Run("graffiti length greater than pubkeys", func(t *testing.T) {
		fn, err := GetGraffitiFunc(pubkeys, []string{randomString(10), randomString(15), randomString(20)}, false)
		require.Nil(t, fn)
		require.Error(t, err)
	})

	t.Run("graffiti length greater than 32 characters", func(t *testing.T) {
		fn, err := GetGraffitiFunc(pubkeys, []string{randomString(33)}, false)
		require.Nil(t, fn)
		require.Error(t, err)
	})

	tests := []struct {
		name                string
		graffiti            []string
		disableClientAppend bool
		expected            GraffitiFunc
	}{
		{
			name:                "nil graffiti - with append",
			disableClientAppend: false,
			expected:            getDefaultGraffiti,
		},
		{
			name:                "nil graffiti - without append",
			disableClientAppend: true,
			expected:            getDefaultGraffiti,
		},
		{
			name:                "single graffiti - space for signature - with append",
			graffiti:            []string{randomString(32 - len(obolSignature))},
			disableClientAppend: false,
			expected:            getEqualGraffitiWithAppend,
		},
		{
			name:                "single graffiti - space for signature - without append",
			graffiti:            []string{randomString(32 - len(obolSignature))},
			disableClientAppend: true,
			expected:            getEqualGraffitiWithoutAppend,
		},
		{
			name:                "single graffiti - no space for signature - with append",
			graffiti:            []string{randomString(32 - len(obolSignature) + 1)},
			disableClientAppend: false,
			expected:            getEqualGraffitiWithoutAppend,
		},
		{
			name:                "single graffiti - no space for signature - without append",
			graffiti:            []string{randomString(32 - len(obolSignature) + 1)},
			disableClientAppend: true,
			expected:            getEqualGraffitiWithoutAppend,
		},
		{
			name:     "multiple graffiti",
			graffiti: []string{randomString(32 - len(obolSignature)), randomString(32 - len(obolSignature) + 1)},
			expected: getGraffitiPerValidator,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := GetGraffitiFunc(pubkeys, tt.graffiti, tt.disableClientAppend)
			require.NoError(t, err)
			require.Equal(t, reflect.ValueOf(tt.expected).Pointer(), reflect.ValueOf(fn).Pointer())
		})
	}
}

func TestGetDefaultGraffiti(t *testing.T) {
	pubkeys := []core.PubKey{testutil.RandomCorePubKey(t)}
	graffiti := []string{}

	graffitiBytes := getDefaultGraffiti(pubkeys, pubkeys[0], graffiti, false)
	commitSHA, _ := version.GitCommit()
	var expected [32]byte
	copy(expected[:], fmt.Sprintf("charon/%v-%s", version.Version, commitSHA))

	require.Equal(t, expected, graffitiBytes)
	require.LessOrEqual(t, len(graffitiBytes), 32)
}

func TestGetEqualGraffitiWithAppend(t *testing.T) {
	pubkeys := []core.PubKey{testutil.RandomCorePubKey(t)}
	graffiti := randomString(10)

	graffitiBytes := getEqualGraffitiWithAppend(pubkeys, pubkeys[0], []string{graffiti}, false)
	var expected [32]byte
	copy(expected[:], graffiti+obolSignature)

	require.Equal(t, expected, graffitiBytes)
	require.LessOrEqual(t, len(graffitiBytes), 32)
}

func TestGetEqualGraffitiWithoutAppend(t *testing.T) {
	pubkeys := []core.PubKey{testutil.RandomCorePubKey(t)}
	graffiti := randomString(32 - len(obolSignature) + 1)

	graffitiBytes := getEqualGraffitiWithoutAppend(pubkeys, pubkeys[0], []string{graffiti}, false)
	var expected [32]byte
	copy(expected[:], graffiti)

	require.Equal(t, expected, graffitiBytes)
	require.LessOrEqual(t, len(graffitiBytes), 32)
}

func TestGetGraffitiPerValidator(t *testing.T) {
	pubkeys := []core.PubKey{
		testutil.RandomCorePubKey(t),
		testutil.RandomCorePubKey(t),
		testutil.RandomCorePubKey(t),
	}
	graffiti := []string{randomString(10), randomString(32 - len(obolSignature)), randomString(32 - len(obolSignature) + 1)}

	t.Run("invalid pubkey", func(t *testing.T) {
		graffitiBytes := getGraffitiPerValidator(pubkeys, "invalid_pubkey", graffiti, false)
		expected := getDefaultGraffiti(pubkeys, "", graffiti, false)

		require.Equal(t, expected, graffitiBytes)
		require.LessOrEqual(t, len(graffitiBytes), 32)
	})

	t.Run("graffiti space for signature", func(t *testing.T) {
		graffitiBytes := getGraffitiPerValidator(pubkeys, pubkeys[1], graffiti, false)
		var expected [32]byte
		copy(expected[:], graffiti[1]+obolSignature)

		require.Equal(t, expected, graffitiBytes)
		require.LessOrEqual(t, len(graffitiBytes), 32)
	})

	t.Run("graffiti no space for signature", func(t *testing.T) {
		graffitiBytes := getGraffitiPerValidator(pubkeys, pubkeys[2], graffiti, false)
		var expected [32]byte
		copy(expected[:], graffiti[2])

		require.Equal(t, expected, graffitiBytes)
		require.LessOrEqual(t, len(graffitiBytes), 32)
	})
}
