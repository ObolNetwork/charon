package eth2exp

import (
	"context"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
)

// BeaconCommitteeSubscriptionsSubmitter is the interface for submitting beacon committee subnet subscription requests.
type BeaconCommitteeSubscriptionsSubmitter interface {
	// SubmitBeaconCommitteeSubscriptions subscribes to beacon committees.
	SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*BeaconCommitteeSubscription) ([]BeaconCommitteeSubscriptionResponse, error)
}

// BeaconCommitteeSubscription is the data required for a beacon committee subscription.
type BeaconCommitteeSubscription struct {
	// ValidatorIdex is the index of the validator making the subscription request.
	ValidatorIndex eth2p0.ValidatorIndex
	// Slot is the slot for which the validator is attesting.
	Slot eth2p0.Slot
	// CommitteeIndex is the index of the committee of which the validator is a member at the given slot.
	CommitteeIndex eth2p0.CommitteeIndex
	// CommitteesAtSlot is the number of committees at the given slot.
	CommitteesAtSlot uint64
	// SlotSignature is the slot signature required to calculate whether the validator is an aggregator.
	SlotSignature eth2p0.BLSSignature
}

// BeaconCommitteeSubscriptionResponse is the response from beacon node after submitting BeaconCommitteeSubscription.
type BeaconCommitteeSubscriptionResponse struct {
	// ValidatorIndex is the index of the validator that made the subscription request.
	ValidatorIndex eth2p0.ValidatorIndex
	// IsAggregator indicates whether the validator is an attestation aggregator.
	IsAggregator bool
}
