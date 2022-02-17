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

package cluster

import (
	"context"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/types"
)

/*
Slot-Duty Flow:

              ┌────┐   ┌─────┐   ┌────┐  ┌──────┐
    Decide    │Shed├───►Fetch├───►Cons├──►DutyDB│
              └────┘   └──&<─┘   └─*──┘  └─>┌───┘
                                            │
                                          ┌─▼──┐
    Sign                                  │VAPI◄───VC
                                          └─┬──┘(◄──►RS)
                                            │
                                ┌─────┐  ┌──▼───┐
    Share                       │SigEx◄──►PSigDB│
                                └─<*>─┘  └──┬───┘
                                            │
                                         ┌──▼───┐
    Agg                                  │SigAgg│
                                         └──┬───┘
                                            │
                                         ┌──▼──┐
    BCast                                │BCast│
                                         └─&───┘

   &:Beacon-node client calls
   <:Combine many to one
   *:P2P protocol
   >:Split one to many
*/

// ---------------- types (more this to types package) ---------------------------

// DVID is a distributed validator ID.
type DVID string

// NoDV is a stub indicating no distributed validator ID is present or applicable.
// This is used for block proposer duties that are not split by validator.
const NoDV DVID = ""

// DutyData represents the associated data of a duty.
type DutyData []byte

// DutyDataSet represents a set of duty data's for multiple DVs.
type DutyDataSet map[DVID]DutyData

// SignedDutyData represents a signed duty data.
type SignedDutyData struct {
	DutyData []byte
	Sig      bls_sig.PartialSignature
}

// SignedDutyDataSet represents a set of signed duty data's for multiple DVs.
type SignedDutyDataSet map[DVID]SignedDutyData

// -------------------------- workflow interfaces ----------------------------

// Scheduler triggers the start of a duty workflow.
type Scheduler interface {
	// Subscribe registers a callback for triggering a duty.
	Subscribe(func(context.Context, types.Duty) error)
}

// Fetcher fetches proposed duty data.
type Fetcher interface {
	// Fetch triggers fetching of a duty's proposed data set.
	Fetch(context.Context, types.Duty) error

	// Subscribe registers a callback for proposed duty data set.
	Subscribe(func(context.Context, types.Duty, DutyDataSet) error)
}

// Consensys comes to consensus on proposed duty data.
type Consensys interface {
	// Propose triggers consensus of the proposed duty data set.
	Propose(context.Context, types.Duty, DutyDataSet) error

	// Subscribe registers a callback for resolved (reached consensus) duty data set.
	Subscribe(func(context.Context, types.Duty, DutyDataSet) error)
}

// DutyDB persists duty data and makes it available for querying.
type DutyDB interface {
	// Store stores the duty data set.
	Store(context.Context, types.Duty, DutyDataSet) error

	// Await blocks and returns the duty data set for the DVs when available.
	Await(context.Context, types.Duty, []DVID) (DutyDataSet, error)
}

// ValidatorAPI serves validator clients with duty requests and receives partial signed sets in return.
type ValidatorAPI interface {
	// RegisterSource registers a source of queryable duty data.
	RegisterSource(func(context.Context, types.Duty, []DVID) (DutyDataSet, error))

	// Subscribe registers a callback for partially signed duty set.
	Subscribe(func(context.Context, types.Duty, SignedDutyDataSet) error)
}

// SigDB persists duty data and makes it available for querying.
type SigDB interface {
	// StoreInternal stores an internally received partially signed duty data set.
	StoreInternal(context.Context, types.Duty, SignedDutyDataSet) error

	// StoreExternal stores an externally received partially signed duty data set.
	StoreExternal(context.Context, types.Duty, SignedDutyDataSet) error

	// SubscribeInternal registers a callback when an internal partially signed duty set is stored.
	SubscribeInternal(func(context.Context, types.Duty, SignedDutyDataSet) error)

	// SubscribeThreshold registers a callback when *threshold* partially signed duty is reached for a DV.
	SubscribeThreshold(func(context.Context, types.Duty, DVID, []SignedDutyData) error)
}

// SigEx exchanges partially signed duty data sets.
type SigEx interface {
	// Broadcast broadcasts the partially signed duty data set to all peers.
	Broadcast(context.Context, types.Duty, SignedDutyDataSet) error

	// Subscribe registers a callback when a partially signed duty set is received from a peer.
	Subscribe(func(context.Context, types.Duty, SignedDutyDataSet) error)
}

// SigAgg aggregates threshold partial signatures.
type SigAgg interface {
	// Aggregate aggregates the partially signed duty data for the DV.
	Aggregate(context.Context, types.Duty, DVID, []SignedDutyData) error

	// Subscribe registers a callback for aggregated signatures and duty data.
	Subscribe(func(context.Context, types.Duty, DVID, bls_sig.Signature, []byte) error)
}

// Broadcaster broadcasts aggregated signed duty data to the beacon node.
type Broadcaster interface {
	Broadcast(context.Context, types.Duty, DVID, bls_sig.Signature, []byte) error
}

// ------------------------- stitch workflow ------------------

// StitchFlow stitches the workflow steps together.
func StitchFlow(
	sched Scheduler,
	fetch Fetcher,
	cons Consensys,
	dutyDB DutyDB,
	vapi ValidatorAPI,
	sigDB SigDB,
	sigEx SigEx,
	sigAgg SigAgg,
	bcast Broadcaster,
) {
	sched.Subscribe(fetch.Fetch)
	fetch.Subscribe(cons.Propose)
	cons.Subscribe(dutyDB.Store)
	vapi.RegisterSource(dutyDB.Await)
	vapi.Subscribe(sigDB.StoreInternal)
	sigDB.SubscribeInternal(sigEx.Broadcast)
	sigEx.Subscribe(sigDB.StoreExternal)
	sigDB.SubscribeThreshold(sigAgg.Aggregate)
	sigAgg.Subscribe(bcast.Broadcast)
}
