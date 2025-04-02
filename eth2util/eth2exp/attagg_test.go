// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2exp_test

import (
	"context"
	"encoding/hex"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestIsAttAggregator(t *testing.T) {
	ctx := context.Background()

	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// https://github.com/prysmaticlabs/prysm/blob/8627fe72e80009ae162430140bcfff6f209d7a32/beacon-chain/core/helpers/attestation_test.go#L28
	sig, err := hex.DecodeString("8776a37d6802c4797d113169c5fcfda50e68a32058eb6356a6f00d06d7da64c841a00c7c38b9b94a204751eca53707bd03523ce4797827d9bacff116a6e776a20bbccff4b683bf5201b610797ed0502557a58a65c8395f8a1649b976c3112d15")
	require.NoError(t, err)
	blsSig, err := tblsconv.SignatureFromBytes(sig)
	require.NoError(t, err)

	t.Run("aggregator", func(t *testing.T) {
		// https://github.com/prysmaticlabs/prysm/blob/8627fe72e80009ae162430140bcfff6f209d7a32/beacon-chain/core/helpers/attestation_test.go#L26
		commLen := uint64(3)
		isAgg, err := eth2exp.IsAttAggregator(ctx, bmock, commLen, eth2p0.BLSSignature(blsSig))
		require.NoError(t, err)
		require.True(t, isAgg)
	})

	t.Run("not an aggregator", func(t *testing.T) {
		// https://github.com/prysmaticlabs/prysm/blob/fc509cc220a82efd555704d41aa362903a06ab9e/beacon-chain/core/helpers/attestation_test.go#L39
		commLen := uint64(64)
		isAgg, err := eth2exp.IsAttAggregator(ctx, bmock, commLen, eth2p0.BLSSignature(blsSig))
		require.NoError(t, err)
		require.False(t, isAgg)
	})
}

func TestIsSyncCommAggregator(t *testing.T) {
	ctx := context.Background()

	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// The non-aggregator tests (isAgg: false) are taken from https://github.com/prysmaticlabs/prysm/blob/39a7988e9edbed5b517229b4d66c2a8aab7c7b4d/beacon-chain/sync/validate_sync_contribution_proof_test.go#L336.
	// The aggregator tests (isAgg: true) are taken from https://github.com/prysmaticlabs/prysm/blob/39a7988e9edbed5b517229b4d66c2a8aab7c7b4d/beacon-chain/sync/validate_sync_contribution_proof_test.go#L460.
	tests := []struct {
		sig   string // Sync committee contribution selection proof in hex.
		isAgg bool   // True if the sync committee member is a sync committee aggregator.
	}{
		{
			sig:   "b9251a82040d4620b8c5665f328ee6c2eaa02d31d71d153f4abba31a7922a981e541e85283f0ced387d26e86aef9386d18c6982b9b5f8759882fe7f25a328180d86e146994ef19d28bc1432baf29751dec12b5f3d65dbbe224d72cf900c6831a",
			isAgg: false,
		},
		{
			sig:   "af8ab34c2858244899fd858042f46e05d703933c9882fc2214a860042a51b3e1260d31cb81f250dd13f801ac58cea517133ee06c817cc2fa965844d2ec1c6d07ca7e00cdda1ab381fa2968bcfe03cb7bb9c15a004b1e7ac2ed9bb0090d271556",
			isAgg: false,
		},
		{
			sig:   "b5600ab2d7ba84f3eaab5f747b1528b78d33b7077508e5e180adfd5ac694ac64be5eb7932658e20243f39f67fcaca7410040495a2a676dcee5a7d7fe7d8958fbb3e1149a28f7d0488e39689c5a899f1b282d9b65f4d95bb38a52a0d83dafa98f",
			isAgg: false,
		},
		{
			sig:   "b2c6aac9ea2ba773d0b0a1a8426a6beceee5ea24ba353dc37058e5cee0fa7373f91ecdce94e87656856878c051da413f178385b6254e86c47cc3f57080d2e946c7e9438f6b942bfeecaed8be8bff994d7c4e8611854b2dde90055ae9ad7d4464",
			isAgg: false,
		},
		{
			sig:   "a2dffa81808dd9718efa3316f081b7db2649d6c11947591b264b5dc45e94bbd98ed6c07f7418f6af2be73d0ab8d1b75a1797bf2e5fcb440f985db37c57c418e2ed8270d0e326aa54ff4bff2950cbfd6603b1ae07c6bd2b6c4137cd2ee17fd250",
			isAgg: true,
		},
		{
			sig:   "95c6d8706688a96b1e2d825ffe3eea3dbaa34941580204fd6a5179e8124ef8ec38654c74ea042526a22d819a52030572025a16ecd38d3c975ffd72be2a4378265c5b996c14e50f8bbddd670e17618e498607b5ca85c14a136546bc1f02dce0bb",
			isAgg: true,
		},
		{
			sig:   "a9dbd88a49a7269e91b8ef1296f1e07f87fed919d51a446b67122bfdfd61d23f3f929fc1cd5209bd6862fd60f739b27213fb0a8d339f7f081fc84281f554b190bb49cc97a6b3364e622af9e7ca96a97fe2b766f9e746dead0b33b58473d91562",
			isAgg: true,
		},
		{
			sig:   "99e60f20dde4d4872b048d703f1943071c20213d504012e7e520c229da87661803b9f139b9a0c5be31de3cef6821c080125aed38ebaf51ba9a2e9d21d7fbf2903577983109d097a8599610a92c0305408d97c1fd4b0b2d1743fb4eedf5443f99",
			isAgg: true,
		},
	}

	for _, test := range tests {
		sig, err := hex.DecodeString(test.sig)
		require.NoError(t, err)

		var resp eth2p0.BLSSignature
		copy(resp[:], sig)

		ok, err := eth2exp.IsSyncCommAggregator(ctx, bmock, resp)
		require.NoError(t, err)
		require.Equal(t, ok, test.isAgg)
	}
}
