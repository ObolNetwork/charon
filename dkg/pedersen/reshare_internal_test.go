// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/dkg/share"
	"github.com/obolnetwork/charon/tbls"
)

func TestRestoreDistKeyShare(t *testing.T) {
	// The test data is taken from a real DKG run.
	valPubKey := MustDecodeHex(t, "99a2793fd1c586e70a8a1b9be6c8d5268ae15b5f2bb988ba550ca3be5bd3c18a5c8a10ee8005772df9505c6766d1ecc6")
	secretShare := MustDecodeHex(t, "17820621f172b0ccaf03d79c72fc484603f8b34af4b146979233c3e842057e17")
	pks1 := MustDecodeHex(t, "a433d6b71a9ab19a88b5e657cee2847c16930d6dd0d78d3cab9fc7cbacf59746db7f3607cbbad442717ce7ad345a11c7")
	pks2 := MustDecodeHex(t, "955101ca2f21504c69cd3c3a08c0a738d028960a9d91b2ac199c016b4d29baf41538662b7713c6ef2f6d99f462451c4d")
	pks3 := MustDecodeHex(t, "a6819bff560512e6f5f12140c2ec57c5a8b6f2b2c46f3e39e347a2b4719ebe4b54ffa0add31284e135abaf952186f696")
	pks4 := MustDecodeHex(t, "b875e70aab2aebf248a5d9f9e1fb8116a8d23306fd00d401bfddfd656396b69f5a35c77f0db277cf6d0fc047d14ad1e3")

	sshare := share.Share{
		PubKey:      tbls.PublicKey(valPubKey),
		SecretShare: tbls.PrivateKey(secretShare),
		PublicShares: map[int]tbls.PublicKey{
			1: tbls.PublicKey(pks1),
			2: tbls.PublicKey(pks2),
			3: tbls.PublicKey(pks3),
			4: tbls.PublicKey(pks4),
		},
	}

	dks, err := restoreDistKeyShare(sshare, 3, 0)
	require.NoError(t, err)
	require.Equal(t, 0, dks.Share.I)
	require.Len(t, dks.Commits, 3)

	t.Run("threshold", func(t *testing.T) {
		// Any 3 shares (threshold) should reconstruct the public key.
		delete(sshare.PublicShares, 2)

		dks, err := restoreDistKeyShare(sshare, 3, 0)
		require.NoError(t, err)
		require.Equal(t, 0, dks.Share.I)
		require.Len(t, dks.Commits, 3)
	})

	t.Run("not enough shares", func(t *testing.T) {
		// Only 2 shares are left, which is below threshold.
		delete(sshare.PublicShares, 3)

		_, err := restoreDistKeyShare(sshare, 3, 0)
		require.Error(t, err)
	})
}

func TestValidateReshareNodeCounts(t *testing.T) {
	tests := []struct {
		name          string
		oldNodesCount int
		newNodesCount int
		oldThreshold  int
		reshare       *ReshareConfig
		expectError   bool
		errorContains string
	}{
		{
			name:          "no removals or additions - always valid",
			oldNodesCount: 4,
			newNodesCount: 4,
			oldThreshold:  3,
			reshare:       &ReshareConfig{},
			expectError:   false,
		},
		{
			name:          "removals with enough old nodes",
			oldNodesCount: 3,
			newNodesCount: 3,
			oldThreshold:  3,
			reshare:       &ReshareConfig{RemovedPeers: []peer.ID{"peer1"}},
			expectError:   false,
		},
		{
			name:          "removals with more than threshold old nodes",
			oldNodesCount: 4,
			newNodesCount: 3,
			oldThreshold:  3,
			reshare:       &ReshareConfig{RemovedPeers: []peer.ID{"peer1"}},
			expectError:   false,
		},
		{
			name:          "removals with insufficient old nodes",
			oldNodesCount: 2,
			newNodesCount: 2,
			oldThreshold:  3,
			reshare:       &ReshareConfig{RemovedPeers: []peer.ID{"peer1"}},
			expectError:   true,
			errorContains: "remove operation requires at least threshold nodes",
		},
		{
			name:          "removals with zero old nodes (complete replacement)",
			oldNodesCount: 0,
			newNodesCount: 5,
			oldThreshold:  3,
			reshare:       &ReshareConfig{RemovedPeers: []peer.ID{"peer1"}, AddedPeers: []peer.ID{"peer2"}},
			expectError:   true,
			errorContains: "remove operation requires at least threshold nodes",
		},
		{
			name:          "additions with new nodes joining",
			oldNodesCount: 4,
			newNodesCount: 5,
			oldThreshold:  3,
			reshare:       &ReshareConfig{AddedPeers: []peer.ID{"peer1"}},
			expectError:   false,
		},
		{
			name:          "additions without new nodes joining",
			oldNodesCount: 4,
			newNodesCount: 4,
			oldThreshold:  3,
			reshare:       &ReshareConfig{AddedPeers: []peer.ID{"peer1"}},
			expectError:   true,
			errorContains: "add operation requires new nodes to join",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateReshareNodeCounts(tc.oldNodesCount, tc.newNodesCount, tc.oldThreshold, tc.reshare)
			if tc.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errorContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRestoreCommitsOutOfBounds(t *testing.T) {
	tests := []struct {
		name         string
		publicShares map[int][][]byte
		shareNum     int
		threshold    int
		expectError  bool
	}{
		{
			name: "share number exceeds available shares",
			publicShares: map[int][][]byte{
				0: {[]byte("share0_0"), []byte("share0_1")},
				1: {[]byte("share1_0"), []byte("share1_1")},
				2: {[]byte("share2_0"), []byte("share2_1")},
			},
			shareNum:    2, // Requesting index 2, but only 0 and 1 exist
			threshold:   2,
			expectError: true,
		},
		{
			name: "one node has insufficient shares",
			publicShares: map[int][][]byte{
				0: {[]byte("share0_0"), []byte("share0_1"), []byte("share0_2")},
				1: {[]byte("share1_0"), []byte("share1_1")}, // Only 2 shares
				2: {[]byte("share2_0"), []byte("share2_1"), []byte("share2_2")},
			},
			shareNum:    2, // Node 1 doesn't have index 2
			threshold:   2,
			expectError: true,
		},
		{
			name: "empty shares with non-zero shareNum",
			publicShares: map[int][][]byte{
				0: {},
				1: {},
			},
			shareNum:    0,
			threshold:   1,
			expectError: true,
		},
		{
			name: "valid access within bounds",
			publicShares: map[int][][]byte{
				0: {[]byte("share0_0"), []byte("share0_1"), []byte("share0_2")},
				1: {[]byte("share1_0"), []byte("share1_1"), []byte("share1_2")},
			},
			shareNum:    1,
			threshold:   2,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := restoreCommits(tt.publicShares, tt.shareNum, tt.threshold, nil)

			if tt.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), "insufficient public key shares from node")
			} else if err != nil {
				// Valid cases might still error due to invalid key data,
				// but should not error with bounds message
				require.NotContains(t, err.Error(), "insufficient public key shares")
			}
		})
	}
}
