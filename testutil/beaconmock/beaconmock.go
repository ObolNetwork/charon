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

// Package beaconmock provides a mock beacon node server and client primarily for testing.
//
//   beaconmock.Mock     validatorapi.Router
//  ┌────┬──────────┐      ┌───────────┐
//  │    │HTTPServer◄──────┤ proxy     │
//  │    └────▲─────┐ http │           │           VC
//  │         │     │      │           ◄────────── (validatormock)
//  │         │http │      │ served    │   http    (lighthouse)
//  │      ┌──┴─────┤      │ endpoints │           (teku)
//  │      │HTTPMock│      └────┬──────┘
//  └──────┴────────┘           │go
//         ▲                    │
//         │  ┌─────────────────▼──────┐
//         │go│                        │
//         └──┤core workflow components│
//            │                        │
//            └────────────────────────┘
//
//  HTTPServer: Serves stubs and static.json endpoints. Used by Mock and proxy.
//  HTTPMock: *eth2http.Service client connected to HTTPServer.
//  Mock: Wraps HTTPMock, adds customisable logic. Used by simnet core workflow components.
package beaconmock

import (
	"context"
	"fmt"
	"net/http"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"

	"github.com/obolnetwork/charon/app/errors"
)

// Interface assertions.
var (
	_ HTTPMock                           = (*Mock)(nil)
	_ eth2client.AttestationDataProvider = (*Mock)(nil)
	_ eth2client.AttestationsSubmitter   = (*Mock)(nil)
	_ eth2client.AttesterDutiesProvider  = (*Mock)(nil)
	_ eth2client.ProposerDutiesProvider  = (*Mock)(nil)
	_ eth2client.Service                 = (*Mock)(nil)
	_ eth2client.ValidatorsProvider      = (*Mock)(nil)
)

// New returns a new beacon client mock configured with the default and provided options.
func New(opts ...Option) (Mock, error) {
	// Configure http mock first.
	temp := defaultHTTPMock()
	for _, opt := range opts {
		opt(&temp)
	}
	httpMock, httpServer, err := newHTTPMock(temp.overrides...)
	if err != nil {
		return Mock{}, err
	}

	// Then configure the mock
	mock := defaultMock(httpMock, httpServer, temp.clock)
	for _, opt := range opts {
		opt(&mock)
	}

	return mock, nil
}

// defaultHTTPMock returns a mock with default http mock overrides.
func defaultHTTPMock() Mock {
	// Default to recent genesis for lower slot and epoch numbers.
	genesis := time.Date(2022, 3, 1, 0, 0, 0, 0, time.UTC)
	return Mock{
		clock: clockwork.NewRealClock(),
		overrides: []staticOverride{
			{
				Endpoint: "/eth/v1/config/spec",
				Key:      "CONFIG_NAME",
				Value:    "charon-simnet",
			},
			{
				Endpoint: "/eth/v1/config/spec",
				Key:      "PRESET_BASE",
				Value:    "gnosis", // Using gnosis since has shorter slots per epoch (16)
			},
			{
				Endpoint: "/eth/v1/config/spec",
				Key:      "SLOTS_PER_EPOCH",
				Value:    "16",
			},
			{
				Endpoint: "/eth/v1/beacon/genesis",
				Key:      "genesis_time",
				Value:    fmt.Sprint(genesis.Unix()),
			},
		},
	}
}

// Mock provides a mock beacon client and implements eth2client.Service and many of the eth2client Providers.
// Create a new instance with default behaviour via New and then override any function.
type Mock struct {
	HTTPMock
	httpServer *http.Server
	overrides  []staticOverride
	clock      clockwork.Clock

	AttestationDataFunc    func(context.Context, eth2p0.Slot, eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error)
	AttesterDutiesFunc     func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error)
	ProposerDutiesFunc     func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error)
	SubmitAttestationsFunc func(context.Context, []*eth2p0.Attestation) error
	ValidatorsByPubKeyFunc func(context.Context, string, []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error)
	ValidatorsFunc         func(context.Context, string, []eth2p0.ValidatorIndex) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error)
	GenesisTimeFunc        func(ctx context.Context) (time.Time, error)
	NodeSyncingFunc        func(context.Context) (*eth2v1.SyncState, error)
}

func (m Mock) SubmitAttestations(ctx context.Context, attestations []*eth2p0.Attestation) error {
	return m.SubmitAttestationsFunc(ctx, attestations)
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

func (m Mock) HTTPAddr() string {
	return "http://" + m.httpServer.Addr
}

func (m Mock) Close() error {
	err := m.httpServer.Close()
	if err != nil {
		return errors.Wrap(err, "close server")
	}

	return nil
}
