/*
Copyright © 2021 Obol Technologies Inc.
Copyright © 2020, 2021 Attestant Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package null is a null metrics logger.
package null

import (
	"context"
)

// Service is a metrics service that drops metrics.
type Service struct{}

// New creates a new null metrics service.
func New(ctx context.Context) *Service {
	return &Service{}
}

// Presenter provides the presenter for this service.
func (s *Service) Presenter() string {
	return "null"
}

// NumberCounted is called when a test number is counted.
func (s *Service) NumberCounted() {}

// // JobScheduled is called when a job is scheduled.
// func (s *Service) JobScheduled() {}

// // JobCancelled is called when a scheduled job is cancelled.
// func (s *Service) JobCancelled() {}

// // JobStartedOnTimer is called when a scheduled job is started due to meeting its time.
// func (s *Service) JobStartedOnTimer() {}

// // JobStartedOnSignal is called when a scheduled job is started due to being manually signal.
// func (s *Service) JobStartedOnSignal() {}

// // NewEpoch is called when vouch starts processing a new epoch.
// func (s *Service) NewEpoch() {}

// // BlockDelay provides the delay between the start of a slot and vouch receiving its block.
// func (s *Service) BlockDelay(epochSlot uint, delay time.Duration) {}

// // BeaconBlockProposalCompleted is called when a block proposal process has completed.
// func (s *Service) BeaconBlockProposalCompleted(started time.Time, result string) {}

// // AttestationsCompleted is called when an attestation process has completed.
// func (s *Service) AttestationsCompleted(started time.Time, count int, result string) {}

// // AttestationAggregationCompleted is called when an attestation aggregation process has completed.
// func (s *Service) AttestationAggregationCompleted(started time.Time, result string) {}

// // AttestationAggregationCoverage measures the attestation ratio of the attestation aggregation.
// func (s *Service) AttestationAggregationCoverage(frac float64) {}

// // BeaconCommitteeSubscriptionCompleted is called when an beacon committee subscription process has completed.
// func (s *Service) BeaconCommitteeSubscriptionCompleted(started time.Time, result string) {}

// // BeaconCommitteeSubscribers sets the number of beacon committees to which our validators are subscribed.
// func (s *Service) BeaconCommitteeSubscribers(subscribers int) {}

// // BeaconCommitteeAggregators sets the number of beacon committees for which our validators are aggregating.
// func (s *Service) BeaconCommitteeAggregators(aggregators int) {}

// // Accounts sets the number of accounts in a given state.
// func (s *Service) Accounts(state string, count uint64) {}

// // ClientOperation provides a generic monitor for client operations.
// func (s *Service) ClientOperation(provider string, name string, succeeded bool, duration time.Duration) {
// }

// // StrategyOperation provides a generic monitor for strategy operations.
// func (s *Service) StrategyOperation(strategy string, provider string, operation string, duration time.Duration) {
// }

// // SyncCommitteeAggregationsCompleted is called when a sync committee aggregation process has completed.
// func (s *Service) SyncCommitteeAggregationsCompleted(started time.Time, count int, result string) {
// }

// // SyncCommitteeMessagesCompleted is called when a sync committee message process has completed.
// func (s *Service) SyncCommitteeMessagesCompleted(started time.Time, count int, result string) {
// }

// // SyncCommitteeSubscriptionCompleted is called when a sync committee subscription process has completed.
// func (s *Service) SyncCommitteeSubscriptionCompleted(started time.Time, result string) {
// }

// // SyncCommitteeSubscribers sets the number of sync committees to which our validators are subscribed.
// func (s *Service) SyncCommitteeSubscribers(subscribers int) {
// }
