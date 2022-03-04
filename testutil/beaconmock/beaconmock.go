// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package beaconmock provides a mock beacon client primarily for testing.
package beaconmock

import (
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
)

// Interface assertions.
var (
	_ eth2client.Service                 = (*Mock)(nil)
	_ eth2client.NodeSyncingProvider     = (*Mock)(nil)
	_ eth2client.GenesisTimeProvider     = (*Mock)(nil)
	_ eth2client.ValidatorsProvider      = (*Mock)(nil)
	_ eth2client.SlotsPerEpochProvider   = (*Mock)(nil)
	_ eth2client.SlotDurationProvider    = (*Mock)(nil)
	_ eth2client.AttesterDutiesProvider  = (*Mock)(nil)
	_ eth2client.ProposerDutiesProvider  = (*Mock)(nil)
	_ eth2client.AttestationDataProvider = (*Mock)(nil)
)

// New returns a new beacon client mock configured with the default and provided options.
func New(opts ...Option) Mock {
	mock := defaultMock()
	for _, opt := range opts {
		opt(&mock)
	}

	return mock
}

// Mock provides a mock beacon client and implements eth2client.Service and many of the eth2client Providers.
// Create a new instance with default behaviour via New and then override any function.
type Mock struct {
	ProposerDutiesFunc     func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error)
	AttesterDutiesFunc     func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error)
	AttestationDataFunc    func(context.Context, eth2p0.Slot, eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error)
	SlotDurationFunc       func(context.Context) (time.Duration, error)
	SlotsPerEpochFunc      func(context.Context) (uint64, error)
	ValidatorsFunc         func(context.Context, string, []eth2p0.ValidatorIndex) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error)
	ValidatorsByPubKeyFunc func(context.Context, string, []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error)
	GenesisTimeFunc        func(context.Context) (time.Time, error)
	NodeSyncingFunc        func(context.Context) (*eth2v1.SyncState, error)
}

func (m Mock) AttestationData(ctx context.Context, slot eth2p0.Slot, committeeIndex eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error) {
	return m.AttestationDataFunc(ctx, slot, committeeIndex)
}

func (m Mock) ProposerDuties(ctx context.Context, epoch eth2p0.Epoch, validatorIndices []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
	return m.ProposerDutiesFunc(ctx, epoch, validatorIndices)
}

func (m Mock) AttesterDuties(ctx context.Context, epoch eth2p0.Epoch, validatorIndices []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
	return m.AttesterDutiesFunc(ctx, epoch, validatorIndices)
}

func (m Mock) SlotDuration(ctx context.Context) (time.Duration, error) {
	return m.SlotDurationFunc(ctx)
}

func (m Mock) SlotsPerEpoch(ctx context.Context) (uint64, error) {
	return m.SlotsPerEpochFunc(ctx)
}

func (m Mock) Validators(ctx context.Context, stateID string, validatorIndices []eth2p0.ValidatorIndex) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
	return m.ValidatorsFunc(ctx, stateID, validatorIndices)
}

func (m Mock) ValidatorsByPubKey(ctx context.Context, stateID string, validatorPubKeys []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
	return m.ValidatorsByPubKeyFunc(ctx, stateID, validatorPubKeys)
}

func (m Mock) GenesisTime(ctx context.Context) (time.Time, error) {
	return m.GenesisTimeFunc(ctx)
}

func (m Mock) NodeSyncing(ctx context.Context) (*eth2v1.SyncState, error) {
	return m.NodeSyncingFunc(ctx)
}

func (Mock) Name() string {
	return "beacon-mock"
}

func (Mock) Address() string {
	return "mock-address"
}
