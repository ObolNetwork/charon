// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

//nolint:all // pseudo code
package validatormock

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/eth2util/signing"
)

// PseudoSyncCommContributionFlow is an example of how the Sync Committee Contribution
// flow works for the v1 and DVT v2 beacon api.
func PseudoSyncCommContributionFlow(t *testing.T, supportDVT bool) {
	// See spec: https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#sync-committees

	ctx := context.Background()
	eth2Cl, _ := mock.New(ctx) // Error handling omitted for brevity.

	// Given a set of validators with private keys
	var valIdxs []eth2p0.ValidatorIndex
	var signFunc SignFunc

	// For some epoch, either the current or the next epoch.
	var epoch eth2p0.Epoch

	// Calculate current sync committee period start and end.
	spec, _ := eth2Cl.Spec(ctx)
	periodInt, _ := spec["EPOCHS_PER_SYNC_COMMITTEE_PERIOD"].(int)

	period := eth2p0.Epoch(periodInt)

	startEpoch := (epoch / period) * period
	endEpoch := startEpoch + period

	// Get the sync committee duties for this epoch.

	// One option is to fetch the sync committee duties for a subset of validators
	duties, _ := eth2Cl.SyncCommitteeDuties(ctx, epoch, valIdxs)
	for _, duty := range duties {
		// Note SyncCommitteeDuty contains a public key which charon needs to intercept/swap.
		// Note that each validator could have multiple indeces in the sync committee.
		// Note that validators not in the committee is omitted from the response.
		t.Logf("SyncComm Duty VIdx=%v, ValSyncCommIdx=%v",
			duty.ValidatorIndex, duty.ValidatorSyncCommitteeIndices)
	}

	// Another option is to fetch the whole sync committee duty itself.
	// Note that the ValidatorAggregates field is probably the subnets...?
	syncCommittee, _ := eth2Cl.SyncCommitteeAtEpoch(ctx, "head", epoch)

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
	_ = eth2Cl.SubmitSyncCommitteeSubscriptions(ctx, subs)

	// At 1/3 into each slot in sync committee period, submit a sync committee message.
	// Get the current head block root (note there are probably better ways to do this).
	var slot eth2p0.Slot // Note the spec mentioned something about previous slot (slot-1).

	state, _ := eth2Cl.BeaconState(ctx, "head")

	var headBlockRoot eth2p0.Root
	copy(headBlockRoot[:], state.Bellatrix.BlockRoots[0])

	// Create, sign and submit sync committee message
	signingRoot, _ := signing.GetDataRoot(ctx, nil, signing.DomainSyncCommittee, epoch, headBlockRoot)

	var msgs []*altair.SyncCommitteeMessage
	for _, duty := range duties {
		sig, _ := signFunc(duty.PubKey, signingRoot[:])

		msgs = append(msgs, &altair.SyncCommitteeMessage{
			Slot:            slot,
			BeaconBlockRoot: headBlockRoot,
			ValidatorIndex:  duty.ValidatorIndex,
			Signature:       sig,
		})
	}
	_ = eth2Cl.SubmitSyncCommitteeMessages(ctx, msgs)

	// For each slot, some validators are also aggregators and need to submit contributions.
	// This can be calculated at any time in the sync committee period after the duties have been fetched.

	syncCommSize, _ := spec["SYNC_COMMITTEE_SIZE"].(uint64)
	subnetCount, _ := spec["SYNC_COMMITTEE_SUBNET_COUNT"].(uint64)

	type aggregator struct {
		ValidatorIndex eth2p0.ValidatorIndex
		Pubkey         eth2p0.BLSPubKey
		SelectionProof eth2p0.BLSSignature
	}
	aggsPerSubComm := make(map[uint64][]aggregator)
	var selectionReqs []*SyncCommitteeSelection // Only used if supporting DVT
	for _, duty := range duties {
		// Each validator can be part of multiple subcommittees.
		for _, syncCommitteeIdx := range duty.ValidatorSyncCommitteeIndices {
			// Create selection data
			subcommittee := uint64(syncCommitteeIdx) / (syncCommSize / subnetCount)
			data := &altair.SyncAggregatorSelectionData{
				Slot:              slot,
				SubcommitteeIndex: subcommittee,
			}
			root, _ := data.HashTreeRoot()

			// Create selection proof
			signingRoot, _ := signing.GetDataRoot(ctx, nil, signing.DomainSyncCommitteeSelectionProof, epoch, root)

			sig, _ := signFunc(duty.PubKey, signingRoot[:])

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
			// This is a batch endpoint that much be called at roughly the same time by all VCs in the cluster,
			// so cache all the requests until the start of the slot.
			selectionReqs = append(selectionReqs, &SyncCommitteeSelection{
				ValidatorIndex: duty.ValidatorIndex,
				Data:           data,
				SelectionProof: sig,
				IsAggregator:   false, // This value can optionally be calculated even though we ignore it and use that from the response.
			})
		}
	}

	// Instead of calculating aggregator locally, VCs supporting DVT need to request this from the upstream middleware DVT client.
	// By convention, this MUST happen at the start of the slot, since all VCs need to do this at the same.
	if supportDVT {
		selections, _ := SyncCommitteeSelections(ctx, selectionReqs) // This is the new proposed endpoint!

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
		contrib, _ := eth2Cl.SyncCommitteeContribution(ctx, slot, subcommittee, headBlockRoot)

		epoch, _ := epochFromSlot(ctx, nil, contrib.Slot)

		// Sign by each aggregator in the subcommittee
		for _, agg := range aggregators {
			proof := &altair.ContributionAndProof{
				AggregatorIndex: agg.ValidatorIndex,
				Contribution:    contrib,
				SelectionProof:  agg.SelectionProof,
			}

			root, _ := proof.HashTreeRoot()

			signingRoot, _ := signing.GetDataRoot(ctx, nil, signing.DomainContributionAndProof, epoch, root)

			sig, _ := signFunc(agg.Pubkey, signingRoot[:])

			contribs = append(contribs, &altair.SignedContributionAndProof{
				Message:   proof,
				Signature: sig,
			})
		}
	}

	// Submit contributions
	_ = eth2Cl.SubmitSyncCommitteeContributions(ctx, contribs)
}

func isSyncCommAggregator(ctx context.Context, t *testing.T, eth2Cl *mock.Service, sig eth2p0.BLSSignature) bool {
	spec, _ := eth2Cl.Spec(ctx)

	syncCommitteeSize, _ := spec["SYNC_COMMITTEE_SIZE"].(uint64)
	syncCommitteeSubnetCount, _ := spec["SYNC_COMMITTEE_SUBNET_COUNT"].(uint64)
	targetAggregatorsPerSyncCommittee, _ := spec["TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE"].(uint64)

	modulo := syncCommitteeSize / syncCommitteeSubnetCount / targetAggregatorsPerSyncCommittee
	if modulo < 1 {
		modulo = 1
	}

	sigHash := sha256.New()
	_, _ = sigHash.Write(sig[:])

	hash := sigHash.Sum(nil)

	return binary.LittleEndian.Uint64(hash[:8])%modulo == 0
}

// SyncCommitteeSelection is the new proposed endpoint request and response type.
type SyncCommitteeSelection struct {
	// ValidatorIndex identifies the validator. It is required for signature verification (to find the pubkey) and for DVT signature aggregate.
	ValidatorIndex eth2p0.ValidatorIndex
	// Data is the selection data used to calculate the selection proof signature. It is also required for signature verification.
	Data *altair.SyncAggregatorSelectionData
	// SelectionProof is the selection data signature proving the validator is an aggregator for this sync contribution subcommittee and slot.
	SelectionProof eth2p0.BLSSignature
	// IsAggregator indicates whether the validator is an sync committee contribution aggregator.
	IsAggregator bool
}

// SyncCommitteeSelections is the new proposed endpoint that returns aggregated sync committee selections
// for the provided partial selections.
//
// Note endpoint MUST be called at the start of the slot, since all VCs in the cluster need to do it at the same time.
// This is by convention, to ensure timely successful aggregation.
//
// Note this is a completely new endpoint, there is no v1 equivalent.
func SyncCommitteeSelections(ctx context.Context, partials []*SyncCommitteeSelection) ([]*SyncCommitteeSelection, error) {
	// This would call a new v2 BN API endpoint: POST /eth/v2/validator/sync_committee_selections

	// The charon middleware would do the following (error handling omitted):

	var resp []*SyncCommitteeSelection
	for _, selection := range partials {
		// Verify partial selection proof
		if err := verifySelectionProof(ctx, selection); err != nil {
			return nil, err
		}

		// Store partial selection
		storePrepareDutySyncContributionPartialSig(selection)

		aggregatedReq := awaitAggregatedDutySyncContribution(selection.Data.Slot)

		// Calculate isAggregator
		aggregatedReq.IsAggregator = isSyncCommAggregator(ctx, nil, nil, aggregatedReq.SelectionProof)

		resp = append(resp, aggregatedReq)
	}

	return resp, nil
}

func verifySelectionProof(ctx context.Context, partial *SyncCommitteeSelection) error {
	root, _ := partial.Data.HashTreeRoot()

	epoch, _ := epochFromSlot(ctx, nil, partial.Data.Slot)

	signingRoot, _ := signing.GetDataRoot(ctx, nil, signing.DomainSyncCommitteeSelectionProof, epoch, root)

	// Get public share from partial.ValidatorIndex
	var pubkey eth2p0.BLSPubKey

	return verifySignature(partial.SelectionProof, pubkey, signingRoot[:])
}

// storePrepareDutySyncContributionPartialSig stores the partial sync committee selection proof for aggregation when possible.
func storePrepareDutySyncContributionPartialSig(*SyncCommitteeSelection) {}

// awaitAggregatedDutySyncContribution blocks and returns a cluster aggregated SyncCommitteeSelection.
func awaitAggregatedDutySyncContribution(eth2p0.Slot) *SyncCommitteeSelection {
	return &SyncCommitteeSelection{}
}

func verifySignature(eth2p0.BLSSignature, eth2p0.BLSPubKey, []byte) error {
	return nil
}
