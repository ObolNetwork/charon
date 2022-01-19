package crypto

import (
	"testing"

	"github.com/prysmaticlabs/prysm/v2/beacon-chain/core/helpers"
	"github.com/prysmaticlabs/prysm/v2/beacon-chain/core/signing"
	"github.com/prysmaticlabs/prysm/v2/crypto/bls"
	"github.com/prysmaticlabs/prysm/v2/encoding/bytesutil"
	ethpb "github.com/prysmaticlabs/prysm/v2/proto/prysm/v1alpha1"
	"github.com/stretchr/testify/require"
)

func TestTBLSAggregation(t *testing.T) {
	// Create Attestation Data Object
	beaconBlockRoot := bytesutil.ToBytes32([]byte("A"))
	targetRoot := bytesutil.ToBytes32([]byte("B"))
	sourceRoot := bytesutil.ToBytes32([]byte("C"))
	attestationData := &ethpb.AttestationData{
		BeaconBlockRoot: beaconBlockRoot[:],
		Source:          &ethpb.Checkpoint{Root: sourceRoot[:], Epoch: 3},
		Target:          &ethpb.Checkpoint{Root: targetRoot[:]},
	}

	signingRoot, err := signing.ComputeSigningRoot(attestationData, make([]byte, 32))
	require.NoError(t, err)

	// Creating Threshold BLS Key shares
	threshold := 3
	numberOfShares := 5
	t.Run("Sign and verify attestations", func(t *testing.T) {
		priPoly, _ := NewTBLSPoly(threshold)
		priKeyShares := priPoly.Shares(numberOfShares)
		var atts []*ethpb.Attestation
		var pubKeys []bls.PublicKey

		for _, priKeyShare := range priKeyShares {
			priKeyBinary, err := priKeyShare.V.MarshalBinary()
			require.NoError(t, err)

			priKey, err := bls.SecretKeyFromBytes(priKeyBinary)
			require.NoError(t, err)

			pubkey := priKey.PublicKey()
			pubKeys = append(pubKeys, pubkey)

			sig := priKey.Sign(signingRoot[:])
			att := &ethpb.Attestation{
				Data:      attestationData,
				Signature: sig.Marshal(),
			}
			atts = append(atts, att)
		}
		aggSig, err := helpers.AggregateSignature(atts)
		require.NoError(t, err)

		require.Equal(t, true, aggSig.FastAggregateVerify(pubKeys, signingRoot))
	})
}
