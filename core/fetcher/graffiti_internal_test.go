// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package fetcher

import (
	"errors"
	"fmt"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap/mocks"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

func TestFetchBeaconNodeToken(t *testing.T) {
	t.Run("fetch token error", func(t *testing.T) {
		eth2Cl := mocks.NewClient(t)
		eth2Cl.On("NodeVersion", mock.Anything, mock.Anything).Return(nil, errors.New("")).Once()
		token := fetchBeaconNodeToken(eth2Cl)
		require.Equal(t, "", token)
	})

	t.Run("fetch token unexpected response", func(t *testing.T) {
		eth2Cl := mocks.NewClient(t)
		eth2Cl.On("NodeVersion", mock.Anything, mock.Anything).Return(&eth2api.Response[string]{Data: "IncorrectUserAgent"}, nil).Once()
		token := fetchBeaconNodeToken(eth2Cl)
		require.Equal(t, "", token)
	})

	t.Run("fetch token not predicted in map", func(t *testing.T) {
		eth2Cl := mocks.NewClient(t)
		eth2Cl.On("NodeVersion", mock.Anything, mock.Anything).Return(&eth2api.Response[string]{Data: "Dune/v1.3 (Windows)"}, nil).Once()
		token := fetchBeaconNodeToken(eth2Cl)
		require.Equal(t, "", token)
	})

	t.Run("fetch token", func(t *testing.T) {
		eth2Cl := mocks.NewClient(t)
		eth2Cl.On("NodeVersion", mock.Anything, mock.Anything).Return(&eth2api.Response[string]{Data: "Lighthouse/v0.1.5 (Linux x86_64)"}, nil).Once()
		token := fetchBeaconNodeToken(eth2Cl)
		require.Equal(t, "LH", token)
	})
}

func TestBuildGraffiti(t *testing.T) {
	t.Run("disable client append", func(t *testing.T) {
		graffiti := testutil.RandomBytesAsString(10)
		token := "BN"
		result := buildGraffiti(graffiti, token, true)

		var expected [32]byte
		copy(expected[:], graffiti)

		require.Equal(t, expected, result)
	})

	t.Run("space for both signatures", func(t *testing.T) {
		graffiti := testutil.RandomBytesAsString(10)
		token := "BN"
		result := buildGraffiti(graffiti, token, false)

		var expected [32]byte
		copy(expected[:], graffiti+obolToken+token)

		require.Equal(t, expected, result)
	})

	t.Run("space for obolToken only", func(t *testing.T) {
		graffiti := testutil.RandomBytesAsString(32 - len(obolToken))
		token := "BN"
		result := buildGraffiti(graffiti, token, false)

		var expected [32]byte
		copy(expected[:], graffiti+obolToken)

		require.Equal(t, expected, result)
	})

	t.Run("no space for any signature", func(t *testing.T) {
		graffiti := testutil.RandomBytesAsString(32 - len(obolToken) + 1)
		token := "BN"
		result := buildGraffiti(graffiti, token, false)

		var expected [32]byte
		copy(expected[:], graffiti)

		require.Equal(t, expected, result)
	})
}

func TestDefaultGraffiti(t *testing.T) {
	defaultGraffiti := defaultGraffiti()

	var graffitiBytes [32]byte
	commitSHA, _ := version.GitCommit()
	copy(graffitiBytes[:], fmt.Sprintf("charon/%v-%s", version.Version, commitSHA))

	require.Equal(t, graffitiBytes, defaultGraffiti)
}

func TestGetGraffiti(t *testing.T) {
	pubkeys := []core.PubKey{testutil.RandomCorePubKey(t), testutil.RandomCorePubKey(t), testutil.RandomCorePubKey(t)}
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
}

func TestNewGraffitiBuilder(t *testing.T) {
	pubkeys := []core.PubKey{testutil.RandomCorePubKey(t), testutil.RandomCorePubKey(t), testutil.RandomCorePubKey(t)}

	t.Run("graffiti length greater than pubkeys", func(t *testing.T) {
		eth2Cl := mocks.NewClient(t)
		builder, err := NewGraffitiBuilder(pubkeys, []string{testutil.RandomBytesAsString(10), testutil.RandomBytesAsString(15), testutil.RandomBytesAsString(20), testutil.RandomBytesAsString(25)}, false, eth2Cl)
		require.Nil(t, builder)
		require.Error(t, err)
	})

	t.Run("graffiti length lesser than pubkeys", func(t *testing.T) {
		eth2Cl := mocks.NewClient(t)
		builder, err := NewGraffitiBuilder(pubkeys, []string{testutil.RandomBytesAsString(10), testutil.RandomBytesAsString(15)}, false, eth2Cl)
		require.Nil(t, builder)
		require.Error(t, err)
	})

	t.Run("graffiti length greater than 32 characters", func(t *testing.T) {
		eth2Cl := mocks.NewClient(t)
		builder, err := NewGraffitiBuilder(pubkeys, []string{testutil.RandomBytesAsString(33)}, false, eth2Cl)
		require.Nil(t, builder)
		require.Error(t, err)
	})

	t.Run("nil graffiti", func(t *testing.T) {
		eth2Cl := mocks.NewClient(t)
		builder, err := NewGraffitiBuilder(pubkeys, nil, false, eth2Cl)
		require.NoError(t, err)

		for _, pubkey := range pubkeys {
			require.Equal(t, defaultGraffiti(), builder.GetGraffiti(pubkey))
		}
	})

	t.Run("single graffiti with space for signature", func(t *testing.T) {
		graffiti := testutil.RandomBytesAsString(32 - len(obolToken))
		eth2Cl := mocks.NewClient(t)
		eth2Cl.On("NodeVersion", mock.Anything, mock.Anything).Return(&eth2api.Response[string]{Data: ""}, nil).Once()
		builder, err := NewGraffitiBuilder(pubkeys, []string{graffiti}, false, eth2Cl)
		require.NoError(t, err)

		for _, pubkey := range pubkeys {
			var expected [32]byte
			copy(expected[:], graffiti+obolToken)

			require.Equal(t, expected, builder.GetGraffiti(pubkey))
		}
	})

	t.Run("single graffiti without space for signature", func(t *testing.T) {
		graffiti := testutil.RandomBytesAsString(32 - len(obolToken) + 1)
		eth2Cl := mocks.NewClient(t)
		eth2Cl.On("NodeVersion", mock.Anything, mock.Anything).Return(&eth2api.Response[string]{Data: ""}, nil).Once()
		builder, err := NewGraffitiBuilder(pubkeys, []string{graffiti}, false, eth2Cl)
		require.NoError(t, err)

		for _, pubkey := range pubkeys {
			var expected [32]byte
			copy(expected[:], graffiti)

			require.Equal(t, expected, builder.GetGraffiti(pubkey))
		}
	})

	t.Run("multiple graffiti", func(t *testing.T) {
		graffiti := []string{testutil.RandomBytesAsString(10), testutil.RandomBytesAsString(32 - len(obolToken)), testutil.RandomBytesAsString(32 - len(obolToken) + 1)}
		expectedGraffiti := []string{graffiti[0] + obolToken, graffiti[1] + obolToken, graffiti[2]}
		eth2Cl := mocks.NewClient(t)
		eth2Cl.On("NodeVersion", mock.Anything, mock.Anything).Return(&eth2api.Response[string]{Data: ""}, nil).Once()
		builder, err := NewGraffitiBuilder(pubkeys, graffiti, false, eth2Cl)
		require.NoError(t, err)

		for idx, pubkey := range pubkeys {
			var expected [32]byte
			copy(expected[:], expectedGraffiti[idx])

			require.Equal(t, expected, builder.GetGraffiti(pubkey))
		}
	})
}
