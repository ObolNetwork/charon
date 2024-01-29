// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatormock

import (
	"context"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestGetSubcommittees(t *testing.T) {
	ctx := context.Background()
	bmock, err := beaconmock.New(
		beaconmock.WithSyncCommitteeSize(512),
		beaconmock.WithSyncCommitteeSubnetCount(4),
	)
	require.NoError(t, err)

	duty := &eth2v1.SyncCommitteeDuty{
		PubKey:                        testutil.RandomEth2PubKey(t),
		ValidatorIndex:                0,
		ValidatorSyncCommitteeIndices: []eth2p0.CommitteeIndex{75, 133, 289, 491},
	}

	expected := []eth2p0.CommitteeIndex{0, 1, 2, 3}

	subcommittees, err := getSubcommittees(ctx, bmock, duty)
	require.NoError(t, err)
	require.Equal(t, expected, subcommittees)
}
