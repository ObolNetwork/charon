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

func TestValidateThreshold(t *testing.T) {
	tests := []struct {
		name      string
		nodeCount int
		threshold int
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "valid threshold at BFT minimum (3 nodes)",
			nodeCount: 3,
			threshold: 2, // ceil(2*3/3) = 2
			wantErr:   false,
		},
		{
			name:      "valid threshold at BFT minimum (4 nodes)",
			nodeCount: 4,
			threshold: 3, // ceil(2*4/3) = 3
			wantErr:   false,
		},
		{
			name:      "valid threshold at maximum (equals node count)",
			nodeCount: 5,
			threshold: 5,
			wantErr:   false,
		},
		{
			name:      "valid threshold between minimum and maximum",
			nodeCount: 7,
			threshold: 6, // minimum is 5, max is 7
			wantErr:   false,
		},
		{
			name:      "invalid threshold below BFT minimum",
			nodeCount: 4,
			threshold: 2, // minimum is 3
			wantErr:   true,
			errMsg:    "threshold below minimum Byzantine fault tolerance requirement",
		},
		{
			name:      "invalid threshold exceeds node count",
			nodeCount: 3,
			threshold: 4,
			wantErr:   true,
			errMsg:    "threshold exceeds node count",
		},
		{
			name:      "invalid threshold zero (should be normalized before validation)",
			nodeCount: 4,
			threshold: 0,
			wantErr:   true,
			errMsg:    "threshold below minimum Byzantine fault tolerance requirement",
		},
		{
			name:      "edge case single node (threshold must be 1)",
			nodeCount: 1,
			threshold: 1,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateThreshold(tt.nodeCount, tt.threshold)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
