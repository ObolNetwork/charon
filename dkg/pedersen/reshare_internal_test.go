// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen

import (
	"testing"

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
