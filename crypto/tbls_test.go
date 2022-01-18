package crypto

import (
	"testing"

	"github.com/prysmaticlabs/prysm/v2/beacon-chain/core/helpers"
	"github.com/prysmaticlabs/prysm/v2/beacon-chain/core/signing"
	"github.com/prysmaticlabs/prysm/v2/crypto/bls"
	"github.com/prysmaticlabs/prysm/v2/encoding/bytesutil"
	ethpb "github.com/prysmaticlabs/prysm/v2/proto/prysm/v1alpha1"
	"github.com/stretchr/testify/assert"
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
	t.Run("Sign and verify attestations", func(tt *testing.T) {
		priPoly, _ := NewTBLSPoly(threshold)
		priKeyShares := priPoly.Shares(numberOfShares)
		atts := make([]*ethpb.Attestation, 0, numberOfShares)
		pubKeys := make([]bls.PublicKey, 0, numberOfShares)

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
		require.NoError(tt, err)
		assert.Equal(tt, true, aggSig.FastAggregateVerify(pubKeys, signingRoot))
	})

	// Next steps would be:
	// 1. Sign the signing root with different key shares with all possible
	//    combinations of threshold.
	// 2. Create the signed attestations with partial signatures from Step 1.
	// 3. Merge Signed attestations while aggregating signatures into a final attestation.
	// 4. Verify the Final Signed attestation from prysm's BLS library
}
