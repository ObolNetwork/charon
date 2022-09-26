package validatormock

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/stretchr/testify/require"
	"testing"
)

// PseudoSyncCommContribV1Flow is an example of how the v1 Sync Committee Contribution
// flow works for the v1 beacon api.
func PseudoSyncCommContribV1Flow(t *testing.T) {
	// See spec: https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#sync-committees

	ctx := context.Background()
	eth2Cl, err := mock.New(ctx)
	require.NoError(t, err)

	// Given a set of validators with private keys
	var valIdxs []eth2p0.ValidatorIndex
	var signFunc SignFunc

	// For some epoch, either the current or the next epoch.
	var epoch eth2p0.Epoch

	// Calculate current sync committee period start and end.
	spec, err := eth2Cl.Spec(ctx)
	require.NoError(t, err)
	periodInt, ok := spec["EPOCHS_PER_SYNC_COMMITTEE_PERIOD"].(int)
	require.True(t, ok)

	period := eth2p0.Epoch(periodInt)

	startEpoch := (epoch / period) * period
	endEpoch := startEpoch + period

	// Get the sync committee duties for this epoch.

	// One option is to fetch the sync committee duties for a subset of validators
	duties, err := eth2Cl.SyncCommitteeDuties(ctx, epoch, valIdxs)
	for _, duty := range duties {
		// Note SyncCommitteeDuty contains a public key which charon needs to intercept/swap.
		// Note that each validator could have multiple indeces in the sync committee.
		// Note that validators not in the committee is omitted from the response.
		t.Logf("SyncComm Duty VIdx=%v, ValSyncCommIdx=%v",
			duty.ValidatorIndex, duty.ValidatorSyncCommitteeIndices)
	}

	// Another option is to fetch the whole sync committee duty itself.
	// Note that the ValidatorAggregates field is probably the subnets...?
	syncCommittee, err := eth2Cl.SyncCommitteeAtEpoch(ctx, "head", epoch)
	require.NoError(t, err)
	t.Logf("SyncCommittee len(Validators)=%v, len(ValidatorAggregates)=%v",
		len(syncCommittee.Validators), len(syncCommittee.ValidatorAggregates))
	// Lookup validators in the returned lists.

	// At the start of each epoch in the period, notify the BN to subscribe to the subnet.
	// Doing this repeatedly each epoch in case the BN restarts.

	// Create and then submit subscriptions
	var subs []*eth2v1.SyncCommitteeSubscription
	for _, valIdx := range valIdxs {
		var dutyIdx int // Get the index of this validator in the duty list.

		// Skip validator if not in the list.

		subs = append(subs, &eth2v1.SyncCommitteeSubscription{
			ValidatorIndex:       valIdx,
			SyncCommitteeIndices: duties[dutyIdx].ValidatorSyncCommitteeIndices, // Note that
			UntilEpoch:           endEpoch,
		})
	}
	err = eth2Cl.SubmitSyncCommitteeSubscriptions(ctx, subs)
	require.NoError(t, err)

	// At 1/3 into each slot in sync committee period, submit a sync committee message.
	// Get the current head block root (note there are probably better ways to do this).
	var slot eth2p0.Slot // Note the spec mentioned something about previous slot (slot-1).

	state, err := eth2Cl.BeaconState(ctx, "head")
	require.NoError(t, err)
	var headBlockRoot eth2p0.Root
	copy(headBlockRoot[:], state.Bellatrix.BlockRoots[0])

	// Create, sign and submit sync committee message
	signingRoot, err := signing.GetDataRoot(ctx, nil, signing.DomainSyncCommittee, epoch, headBlockRoot)
	require.NoError(t, err)

	var msgs []*altair.SyncCommitteeMessage
	for _, valIdx := range valIdxs {
		var dutyIdx int // Get the index of this validator in the duty list.

		// Skip validator if not in the list.

		sig, err := signFunc(duties[dutyIdx].PubKey, signingRoot[:])
		require.NoError(t, err)

		msgs = append(msgs, &altair.SyncCommitteeMessage{
			Slot:            slot,
			BeaconBlockRoot: headBlockRoot,
			ValidatorIndex:  valIdx,
			Signature:       sig,
		})
	}
	err = eth2Cl.SubmitSyncCommitteeMessages(ctx, msgs)
	require.NoError(t, err)

	// For each slot, some validators are also aggregators and need to submit contributions.

	syncCommSize, ok := spec["SYNC_COMMITTEE_SIZE"].(uint64)
	require.True(t, ok)
	subnetCount, ok := spec["SYNC_COMMITTEE_SUBNET_COUNT"].(uint64)
	require.True(t, ok)

	for _, valIdx := range valIdxs {
		var dutyIdx int // Get the index of this validator in the duty list.
		// Skip validator if not in the list.

		// Check if isAggregator
		for _, idx := range duties[dutyIdx].ValidatorSyncCommitteeIndices {
			// Create selection data
			root, err := (&altair.SyncAggregatorSelectionData{
				Slot:              slot,
				SubcommitteeIndex: uint64(idx) / (syncCommSize / subnetCount),
			}).HashTreeRoot()
			require.NoError(t, err)

			// Create selection proof
			signingRoot, err := signing.GetDataRoot(ctx, nil, signing.DomainSyncCommitteeSelectionProof, epoch, root)
			require.NoError(t, err)
			sig, err := signFunc(duties[dutyIdx].PubKey, signingRoot[:])
			require.NoError(t, err)

			isAgg := isSyncCommAggregator(ctx, t, eth2Cl, sig)
			
		}

		msgs = append(msgs, &altair.SyncCommitteeMessage{
			Slot:            slot,
			BeaconBlockRoot: headBlockRoot,
			ValidatorIndex:  valIdx,
			Signature:       sig,
		})
	}
}

func isSyncCommAggregator(ctx context.Context, t *testing.T, eth2Cl *mock.Service, sig eth2p0.BLSSignature) bool {
	spec, err := eth2Cl.Spec(ctx)
	require.NoError(t, err)
	syncCommitteeSize, ok := spec["SYNC_COMMITTEE_SIZE"].(uint64)
	require.True(t, ok)
	syncCommitteeSubnetCount, ok := spec["SYNC_COMMITTEE_SUBNET_COUNT"].(uint64)
	require.True(t, ok)
	targetAggregatorsPerSyncCommittee, ok := spec["TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE"].(uint64)
	require.True(t, ok)

	modulo := syncCommitteeSize / syncCommitteeSubnetCount / targetAggregatorsPerSyncCommittee
	if modulo < 1 {
		modulo = 1
	}

	sigHash := sha256.New()
	_, err = sigHash.Write(sig[:])
	require.NoError(t, err)
	hash := sigHash.Sum(nil)

	return binary.LittleEndian.Uint64(hash[:8])%modulo == 0
}
