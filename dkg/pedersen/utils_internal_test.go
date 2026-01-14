// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen

import (
	"testing"

	"github.com/drand/kyber"
	kbls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/share"
	kdkg "github.com/drand/kyber/share/dkg"
	"github.com/stretchr/testify/require"
)

func TestRandomKeyPair(t *testing.T) {
	suite := kbls.NewBLS12381Suite().G1().(kdkg.Suite)
	private, public := randomKeyPair(suite)

	require.NotNil(t, private)
	require.NotNil(t, public)

	private2, public2 := randomKeyPair(suite)
	require.NotEqual(t, private, private2)
	require.NotEqual(t, public, public2)
}

func TestUnmarshalPoint(t *testing.T) {
	suite := kbls.NewBLS12381Suite().G1().(kdkg.Suite)
	_, public := randomKeyPair(suite)
	publicBytes, err := public.MarshalBinary()
	require.NoError(t, err)

	t.Run("valid input", func(t *testing.T) {
		point, err := unmarshalPoint(suite, publicBytes)
		require.NoError(t, err)
		require.NotNil(t, point)
	})

	t.Run("invalid input", func(t *testing.T) {
		_, err = unmarshalPoint(suite, []byte{})
		require.Error(t, err)

		malformedBytes := []byte{0x01, 0x02}
		_, err = unmarshalPoint(suite, malformedBytes)
		require.Error(t, err)
	})
}

func TestDistKeyShareToValidatorPubKey(t *testing.T) {
	suite := kbls.NewBLS12381Suite().G1().(kdkg.Suite)
	private, public := randomKeyPair(suite)

	t.Run("valid input", func(t *testing.T) {
		dkgResult := &kdkg.DistKeyShare{
			Share:   &share.PriShare{I: 1, V: private},
			Commits: []kyber.Point{public},
		}

		pubKey, err := distKeyShareToValidatorPubKey(dkgResult, suite)
		require.NoError(t, err)
		require.NotNil(t, pubKey)

		pubKeyBytes, err := public.MarshalBinary()
		require.NoError(t, err)
		require.Equal(t, pubKeyBytes, pubKey[:])
	})
}

func TestKeyShareToBLS(t *testing.T) {
	suite := kbls.NewBLS12381Suite().G1().(kdkg.Suite)
	private, public := randomKeyPair(suite)

	t.Run("valid input", func(t *testing.T) {
		dkgResult := &kdkg.DistKeyShare{
			Share:   &share.PriShare{I: 1, V: private},
			Commits: []kyber.Point{public},
		}

		privKey, pubKey, err := keyShareToBLS(dkgResult)
		require.NoError(t, err)
		require.NotNil(t, privKey)
		require.NotNil(t, pubKey)

		pubKeyBytes, err := public.MarshalBinary()
		require.NoError(t, err)
		require.Equal(t, pubKeyBytes, pubKey[:])
	})
}
