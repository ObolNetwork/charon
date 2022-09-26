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

// PseudoSyncCommContribV1Flow is an example of how the Sync Committee Contribution
// flow works for the v1 and DVT v2 beacon api.
func PseudoSyncCommContribV1Flow(t *testing.T, supportDVT bool) {
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
	for _, duty := range duties {
		subs = append(subs, &eth2v1.SyncCommitteeSubscription{
			ValidatorIndex:       duty.ValidatorIndex,
			SyncCommitteeIndices: duty.ValidatorSyncCommitteeIndices,
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
	for _, duty := range duties {
		sig, err := signFunc(duty.PubKey, signingRoot[:])
		require.NoError(t, err)

		msgs = append(msgs, &altair.SyncCommitteeMessage{
			Slot:            slot,
			BeaconBlockRoot: headBlockRoot,
			ValidatorIndex:  duty.ValidatorIndex,
			Signature:       sig,
		})
	}
	err = eth2Cl.SubmitSyncCommitteeMessages(ctx, msgs)
	require.NoError(t, err)

	// For each slot, some validators are also aggregators and need to submit contributions.
	// This can be calculated at any time in the sync committee period after the duties have been fetched.

	syncCommSize, ok := spec["SYNC_COMMITTEE_SIZE"].(uint64)
	require.True(t, ok)
	subnetCount, ok := spec["SYNC_COMMITTEE_SUBNET_COUNT"].(uint64)
	require.True(t, ok)

	type aggregator struct {
		ValidatorIndex eth2p0.ValidatorIndex
		Pubkey         eth2p0.BLSPubKey
		SelectionProof eth2p0.BLSSignature
	}
	aggsPerSubComm := make(map[uint64][]aggregator)
	var partialSelections []*PartialSyncCommitteeSelection // Only used if supporting DVT
	for _, duty := range duties {
		// Each validator can be part of multiple subcommittees.
		for _, syncCommitteeIdx := range duty.ValidatorSyncCommitteeIndices {
			// Create selection data
			subcommittee := uint64(syncCommitteeIdx) / (syncCommSize / subnetCount)
			data := &altair.SyncAggregatorSelectionData{
				Slot:              slot,
				SubcommitteeIndex: subcommittee,
			}
			root, err := data.HashTreeRoot()
			require.NoError(t, err)

			// Create selection proof
			signingRoot, err := signing.GetDataRoot(ctx, nil, signing.DomainSyncCommitteeSelectionProof, epoch, root)
			require.NoError(t, err)
			sig, err := signFunc(duty.PubKey, signingRoot[:])
			require.NoError(t, err)

			// Calculate isAggregator directly in legacy non-DVT.
			if !supportDVT {
				if !isSyncCommAggregator(ctx, t, eth2Cl, sig) {
					continue
				}

				// Add aggregator duties per slot.
				aggsPerSubComm[subcommittee] = append(aggsPerSubComm[subcommittee], aggregator{
					ValidatorIndex: duty.ValidatorIndex,
					Pubkey:         duty.PubKey,
					SelectionProof: sig,
				})
			}

			// For DVT a new endpoint needs to be introduced to calculate and provide aggregated selection proofs.
			// This is a batch endpoint, so gather all the requests.
			partialSelections = append(partialSelections, &PartialSyncCommitteeSelection{
				ValidatorIndex:        duty.ValidatorIndex,
				Data:                  data,
				PartialSelectionProof: sig,
			})
		}
	}

	// Instead of calculating aggregator locally, VCs supporting DVT need to request this from the upstream middleware DVT client.
	if supportDVT {
		selections, err := SyncCommitteeSelections(ctx, partialSelections) // This is the new proposed endpoint!
		require.NoError(t, err)

		for _, selection := range selections {
			if !selection.IsAggregator {
				continue
			}

			// Fetch cached pubkey from selection.ValidatorIndex
			var pubkey eth2p0.BLSPubKey

			// Add aggregator duties per slot.
			aggsPerSubComm[selection.Data.SubcommitteeIndex] = append(aggsPerSubComm[selection.Data.SubcommitteeIndex], aggregator{
				ValidatorIndex: selection.ValidatorIndex,
				Pubkey:         pubkey,
				SelectionProof: selection.SelectionProof,
			})
		}
	}

	// At 2/3 into the slot, fetch the contribution per subcommittee, sign it with all applicable validators and then submit it.
	var contribs []*altair.SignedContributionAndProof
	for subcommittee, aggregators := range aggsPerSubComm {
		// Fetch the contribution for the subcommittee.
		contrib, err := eth2Cl.SyncCommitteeContribution(ctx, slot, subcommittee, headBlockRoot)
		require.NoError(t, err)

		epoch, err := epochFromSlot(ctx, nil, contrib.Slot)
		require.NoError(t, err)

		// Sign by each aggregator in the subcommittee
		for _, agg := range aggregators {
			proof := &altair.ContributionAndProof{
				AggregatorIndex: agg.ValidatorIndex,
				Contribution:    contrib,
				SelectionProof:  agg.SelectionProof,
			}

			root, err := proof.HashTreeRoot()
			require.NoError(t, err)

			signingRoot, err := signing.GetDataRoot(ctx, nil, signing.DomainContributionAndProof, epoch, root)
			require.NoError(t, err)

			sig, err := signFunc(agg.Pubkey, signingRoot[:])
			require.NoError(t, err)

			contribs = append(contribs, &altair.SignedContributionAndProof{
				Message:   proof,
				Signature: sig,
			})
		}
	}

	// Submit contributions
	err = eth2Cl.SubmitSyncCommitteeContributions(ctx, contribs)
	require.NoError(t, err)
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

// PartialSyncCommitteeSelection is the new proposed endpoint request type.
type PartialSyncCommitteeSelection struct {
	ValidatorIndex        eth2p0.ValidatorIndex
	Data                  *altair.SyncAggregatorSelectionData
	PartialSelectionProof eth2p0.BLSSignature
}

// AggregatedSyncCommitteeSelection is the new proposed endpoint response type
type AggregatedSyncCommitteeSelection struct {
	ValidatorIndex eth2p0.ValidatorIndex
	Data           *altair.SyncAggregatorSelectionData
	SelectionProof eth2p0.BLSSignature
	IsAggregator   bool
}

// SyncCommitteeSelections is the new proposed endpoint that returns aggregated sync committee selections
// for the provided partial selections.
//
// Note endpoint can be called at any time in the sync committee period so cannot include head beacon block root.
//
// Note this is a completely new endpoint, there is no v1 equivalent.
func SyncCommitteeSelections(ctx context.Context, partials []*PartialSyncCommitteeSelection) ([]*AggregatedSyncCommitteeSelection, error) {
	// This would call a new v2 BN API endpoint: POST /eth/v2/validator/sync_committee_selections

	// The charon middleware would do the following (error handling omitted):

	var resp []*AggregatedSyncCommitteeSelection
	for _, selection := range partials {
		// Verify partial selection proof
		if err := verifySelectionProof(ctx, selection); err != nil {
			return nil, err
		}

		// Create selection proof
		aggregateSelectionProof := aggregatePartialSelectionProof(selection.PartialSelectionProof)

		// Calculate isAggregator
		isAggregator := isSyncCommAggregator(ctx, nil, nil, aggregateSelectionProof)

		resp = append(resp, &AggregatedSyncCommitteeSelection{
			ValidatorIndex: selection.ValidatorIndex,
			Data:           selection.Data,
			SelectionProof: aggregateSelectionProof,
			IsAggregator:   isAggregator,
		})
	}

	return resp, nil
}

func verifySelectionProof(ctx context.Context, partial *PartialSyncCommitteeSelection) error {
	// Create selection data
	root, _ := partial.Data.HashTreeRoot()

	epoch, _ := epochFromSlot(ctx, nil, partial.Data.Slot)

	signingRoot, _ := signing.GetDataRoot(ctx, nil, signing.DomainSyncCommitteeSelectionProof, epoch, root)

	// Get public share from partial.ValidatorIndex
	var pubkey eth2p0.BLSPubKey

	return verifySignature(partial.PartialSelectionProof, pubkey, signingRoot[:])
}

// aggregatePartialSelectionProof returns a DVT threshold aggregated sync committee selection proof from the partial signature.
func aggregatePartialSelectionProof(_ eth2p0.BLSSignature) eth2p0.BLSSignature {
	// DVT Magic!
	var aggregateSelectionProof eth2p0.BLSSignature
	return aggregateSelectionProof
}

func verifySignature(eth2p0.BLSSignature, eth2p0.BLSPubKey, []byte) error {
	return nil
}
