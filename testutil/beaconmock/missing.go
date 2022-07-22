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

package beaconmock

import (
	"context"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
)

// missingEth2Methods defines the set of eth2 methods that are not implements by beaconmock but required by eth2wrap.
// We are opting for runtime errors for beaconmock but compiletime errors for eth2http and eth2multi.
type missingEth2Methods interface {
	AggregateAttestation(ctx context.Context, slot eth2p0.Slot, attestationDataRoot eth2p0.Root) (*eth2p0.Attestation, error)
	SubmitAggregateAttestations(ctx context.Context, aggregateAndProofs []*eth2p0.SignedAggregateAndProof) error
	AttestationPool(ctx context.Context, slot eth2p0.Slot) ([]*eth2p0.Attestation, error)
	BeaconBlockHeader(ctx context.Context, blockID string) (*eth2v1.BeaconBlockHeader, error)
	BeaconBlockRoot(ctx context.Context, blockID string) (*eth2p0.Root, error)
	SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*eth2v1.BeaconCommitteeSubscription) error
	BeaconState(ctx context.Context, stateID string) (*spec.VersionedBeaconState, error)
	BeaconStateRoot(ctx context.Context, stateID string) (*eth2p0.Root, error)
	FarFutureEpoch(ctx context.Context) (eth2p0.Epoch, error)
	Finality(ctx context.Context, stateID string) (*eth2v1.Finality, error)
	SubmitProposalPreparations(ctx context.Context, preparations []*eth2v1.ProposalPreparation) error
	SignedBeaconBlock(ctx context.Context, blockID string) (*spec.VersionedSignedBeaconBlock, error)
	SyncCommitteeContribution(ctx context.Context, slot eth2p0.Slot, subcommitteeIndex uint64, beaconBlockRoot eth2p0.Root) (*altair.SyncCommitteeContribution, error)
	SubmitSyncCommitteeContributions(ctx context.Context, contributionAndProofs []*altair.SignedContributionAndProof) error
	SubmitSyncCommitteeMessages(ctx context.Context, messages []*altair.SyncCommitteeMessage) error
	SubmitSyncCommitteeSubscriptions(ctx context.Context, subscriptions []*eth2v1.SyncCommitteeSubscription) error
	SyncCommittee(ctx context.Context, stateID string) (*eth2v1.SyncCommittee, error)
	SyncCommitteeAtEpoch(ctx context.Context, stateID string, epoch eth2p0.Epoch) (*eth2v1.SyncCommittee, error)
	TargetAggregatorsPerCommittee(ctx context.Context) (uint64, error)
	ValidatorBalances(ctx context.Context, stateID string, validatorIndices []eth2p0.ValidatorIndex) (map[eth2p0.ValidatorIndex]eth2p0.Gwei, error)
}
