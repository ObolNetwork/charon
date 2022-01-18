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
	priPoly, pubPoly := NewTBLSPoly(threshold)
	priKeyShares := priPoly.Shares(numberOfShares)
	pubKeyShares := pubPoly.Shares(numberOfShares)
	for _, priKeyShare := range priKeyShares {
		t.Log("Private key share: ", *priKeyShare)
	}
	for _, pubKeyShare := range pubKeyShares {
		t.Log("Public key share: ", *pubKeyShare)
	}
	t.Log("Signing Root: ", signingRoot)

	// Next steps would be:
	// 1. Sign the signing root with different key shares with all possible
	//    combinations of threshold.
	// 2. Create the signed attestations with partial signatures from Step 1.
	// 3. Merge Signed attestations while aggregating signatures into a final attestation.
	// 4. Verify the Final Signed attestation from prysm's BLS library
}
