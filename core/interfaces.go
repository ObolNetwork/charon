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

package core

import (
	"context"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
)

// Scheduler triggers the start of a duty workflow.
type Scheduler interface {
	// Subscribe registers a callback for fetching a duty.
	Subscribe(func(context.Context, Duty, FetchArgSet) error)
}

// Fetcher fetches proposed unsigned duty data.
type Fetcher interface {
	// Fetch triggers fetching of a proposed duty data set.
	Fetch(context.Context, Duty, FetchArgSet) error

	// Subscribe registers a callback for proposed unsigned duty data sets.
	Subscribe(func(context.Context, Duty, UnsignedDataSet) error)
}

// DutyDB persists unsigned duty data sets and makes it available for querying. It also acts
// as slashing database.
type DutyDB interface {
	// Store stores the unsigned duty data set.
	Store(context.Context, Duty, UnsignedDataSet) error

	// AwaitAttestation blocks and returns the attestation data
	// for the slot and committee index when available.
	AwaitAttestation(ctx context.Context, slot, commIdx int64) (*eth2p0.AttestationData, error)

	// PubKeyByAttestation returns the validator PubKey for the provided attestation data
	// slot, committee index and validator committee index. This allows mapping of attestation
	// data response to validator.
	PubKeyByAttestation(ctx context.Context, slot, commIdx, valCommIdx int64) (PubKey, error)
}

// Consensus abstracts a cluster consensus layer.
type Consensus interface {
	// Propose triggers consensus game of the proposed duty unsigned data set.
	Propose(context.Context, Duty, UnsignedDataSet) error

	// Subscribe registers a callback for resolved (reached consensus) duty unsigned data set.
	Subscribe(func(context.Context, Duty, UnsignedDataSet) error)
}

// ValidatorAPI provides a beacon node API to validator clients. It serves duty data from the
// DutyDB and stores partial signed data in the ParSigDB.
type ValidatorAPI interface {
	// RegisterAwaitAttestation registers a function to query attestation data.
	RegisterAwaitAttestation(func(ctx context.Context, slot, commIdx int64) (*eth2p0.AttestationData, error))

	// RegisterPubKeyByAttestation registers a function to query validator by attestation.
	RegisterPubKeyByAttestation(func(ctx context.Context, slot, commIdx, valCommIdx int64) (PubKey, error))

	// RegisterParSigDB registers a function to store partially signed data sets.
	RegisterParSigDB(func(context.Context, Duty, ParSignedDataSet) error)
}
