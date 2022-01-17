package crypto

import (
	"github.com/prysmaticlabs/prysm/v2/beacon-chain/core/signing"
	"github.com/prysmaticlabs/prysm/v2/encoding/bytesutil"
	ethpb "github.com/prysmaticlabs/prysm/v2/proto/eth/v1"
	"testing"
)

func TestTBLSAggregation(t *testing.T) {
	beaconBlockRoot := bytesutil.ToBytes32([]byte("A"))
	targetRoot := bytesutil.ToBytes32([]byte("B"))
	sourceRoot := bytesutil.ToBytes32([]byte("C"))
	attestationData := &ethpb.AttestationData{
		BeaconBlockRoot: beaconBlockRoot[:],
		Source:          &ethpb.Checkpoint{Root: sourceRoot[:], Epoch: 3},
		Target:          &ethpb.Checkpoint{Root: targetRoot[:]},
	}
	signingRoot, err := signing.ComputeSigningRoot(attestationData, make([]byte, 32))
	if err != nil {
		t.Fatal("Error in signing root: ", err)
	}
	t.Log("Signing Root: ", signingRoot)
}
