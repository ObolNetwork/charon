package crypto

import (
	"testing"

	"github.com/prysmaticlabs/prysm/v2/beacon-chain/core/signing"
	"github.com/prysmaticlabs/prysm/v2/encoding/bytesutil"
	ethpb "github.com/prysmaticlabs/prysm/v2/proto/eth/v1"
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
	tblsScheme := NewTBLSScheme()

	t.Run("Sharing and recovering", func(tt *testing.T) {
		priPoly, pubPoly := NewTBLSPoly(threshold)
		priKeyShares := priPoly.Shares(numberOfShares)
		sigShares := make([][]byte, 0)

		for _, priKeyShare := range priKeyShares {
			sig, err := tblsScheme.Sign(priKeyShare, signingRoot[:])
			require.Nil(tt, err)
			require.Nil(tt, tblsScheme.VerifyPartial(pubPoly, signingRoot[:], sig))

			idx, err := tblsScheme.IndexOf(sig)
			require.NoError(tt, err)
			require.Equal(tt, priKeyShare.I, idx)

			sigShares = append(sigShares, sig)
		}

		sig, err := tblsScheme.Recover(pubPoly, signingRoot[:], sigShares, threshold, numberOfShares)
		require.Nil(tt, err)

		err = tblsScheme.VerifyRecovered(pubPoly.Commit(), signingRoot[:], sig)
		require.Nil(tt, err)
	})

	// Next steps would be:
	// 1. Sign the signing root with different key shares with all possible
	//    combinations of threshold.
	// 2. Create the signed attestations with partial signatures from Step 1.
	// 3. Merge Signed attestations while aggregating signatures into a final attestation.
	// 4. Verify the Final Signed attestation from prysm's BLS library
}
