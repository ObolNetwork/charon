# Charon Architecture

This document describes the Charon middleware architecture both from cluster level and a node level.

## Cluster Architecture

```
                ┌────┐    ┌────┐   ┌────┐
                │BN#1│    │BN#2│   │BN#n│
                └─▲──┘    └─▲──┘   └─▲──┘
                  │         │        │
       ┌──────────┼─────────┼────────┼──────┐
       │Charon    │         │        │      │
       │Cluster┌──┴───┐  ┌──┴───┐ ┌──┴───┐  │
       │       │ CN#1 │  │ CN#2 │ │ CN#n │  │
       │       │    ◄─┼──┼─►  ◄─┼─┼─►    │  │
       │  ┌────┼──────┼──┼──────┼─┼──────┼┐ │
       │  │DV#1│CV#1/1│  │CV#2/1│ │CV#n/1││ │
       │  └────┼──────┼──┼──────┼─┼──────┼┘ │
       │       │      │  │      │ │      │  │
       │  ┌────┼──────┼──┼──────┼─┼──────┼┐ │
       │  │DV#2│CV#1/2│  │CV#2/2│ │CV#n/2││ │
       │  └────┼──────┼──┼──────┼─┼──────┼┘ │
       │       │      │  │      │ │      │  │
       │  ┌────┼──────┼──┼──────┼─┼──────┼┐ │
       │  │DV#m│CV#1/m│  │CV#2/m│ │CV#n/m││ │
       │  └────┼──────┼──┼──────┼─┼──────┼┘ │
       │       └──▲───┘  └──▲───┘ └──▲───┘  │
       │          │         │        │      │
       └──────────┼─────────┼────────┼──────┘
                  │         │        │
                ┌─┴──┐    ┌─┴──┐   ┌─┴──┐
                │VC#1│    │VC#2│   │VC#n│
                └────┘    └────┘   └────┘
                PS#1/1    PS#2/1   PS#n/1
                PS#1/2    PS#2/2   PS#n/2
                PS#1/m    PS#2/m   PS#n/m
```
- **CN**: `n` physical charon nodes (peers)
- **BN**: `+-n` physical beacon nodes (can be more/less)
- **DV**: `m` logical distributed validators (`m x 32` ETH staked)
- **CV**: `nxm` logical co-validators (`n` per DV, `m` per CN)
- **VC**: `n` physical validator clients (`1` per CN)
- **PS**: `nxm` physical private shares (`m` per VC, `n` per DV)
- Not shown:
  - `t` threshold signatures required (per DV)
  - `ceil(n/3)-1` charon nodes available and honest (when using BFT consensus)

## Charon Node Core Workflow

Charon core business logic is modelled as a workflow, with a duty being performed in a slot as the “unit of work”.
```
Core Workflow
          ┌─────┐  ┌─────┐  ┌────┐  ┌──────┐
  Decide  │Sched├──►Fetch├──►Cons├──►DutyDB│
          └─&───┘  └─&─┬─┘  └─*──┘  └──▲───┘
                       │               │
                       │            ┌──┴─┐
  Sign                 │            │VAPI◄───VC
                       │            └──┬─┘
                       │               │
                       │   ┌─────┐  ┌──▼──┐
  Share                │   │SigEx◄──►SigDB│
                       │   └──*──┘  └──┬──┘
                       │               │
                       │   ┌─────┐  ┌──▼───┐
  Agg                  └───►AggDB◄──┤SigAgg│
                           └─────┘  └──┬───┘
                                       │
                                    ┌──▼──┐
  BCast                             │BCast│
                                    └─&───┘

  &:Beacon-node client calls
  *:P2P protocol
```
### Duty
As per the Ethereum consensus [spec](https://github.com/ethereum/consensus-specs/blob/v1.1.0-alpha.2/specs/phase0/validator.md#beacon-chain-responsibilities):

> ℹ️ A validator has two primary responsibilities to the beacon chain: [proposing blocks](https://github.com/ethereum/consensus-specs/blob/02b32100ed26c3c7a4a44f41b932437859487fd2/specs/phase0/validator.md#block-proposal)
> and [creating attestations](https://github.com/ethereum/consensus-specs/blob/02b32100ed26c3c7a4a44f41b932437859487fd2/specs/phase0/validator.md#attesting).
> Proposals happen infrequently, whereas attestations should be created once per epoch.

Even though the validator has different duties, they all follow the same process, we can therefore model the core business
logic as single workflow being performed on an abstract duty. A duty is always performed in a specific slot.

A duty therefore has a slot and a type and is defined as:
```go
// Duty defines a unit of work.
type Duty struct {
  // Slot is the Ethereum consensus slot of the duty.
  Slot int64
  // Type is the type of duty.
  Type DutyType
}
```

We define the following duty types:

- `type DutyType int`:
- `DutyProposer = 1`: Proposing a block
- `DutyAttester = 2`: Creating an attestation
- `DutyRandao = 3`: Creating a randao reveal signature required as input to DutyProposer
- `DutyAggregator = 4`: Aggregating attestations

> ℹ️ Duty is on a cluster level, not a DV level. A duty defines the “unit of work” for the whole cluster,
> not just a single DV. This allows the workflow to aggregate and batch multiple DVs in some steps, specifically consensus.
> Which is critical for clusters with a large number of DVs.

### Scheduler

The scheduler is the initiator of a duty in the core workflow. It is responsible for starting a duty at the optimal time by calling the `fetcher`.

It does so by first calling [Get attester duties](https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi/getAttesterDuties)
and [Get block proposer](https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi/getProposerDuties) duties on the beacon API
at the start of each epoch for the next epoch. It has access to the cluster manifest, and can therefore calculate which
duties need to be performed by which DVs at which slots.

Note the `DutyRandao` isn’t scheduled by the scheduler, since it is initiated directly by VC at the start of the epoch.

> 🏗️ TODO: Define the exact timing requirements for different duties.

The scheduler interface is defined as:
```go
// Scheduler triggers the start of a duty workflow.
type Scheduler interface {
  // Subscribe registers a callback for triggering a duty.
  Subscribe(func(context.Context, types.Duty) error)
}
```
> ℹ️ Components of the workflow are decoupled from each other. They are stitched together by callback subscriptions.
> This improves testability and avoids the need for mocks. It also allows defining both inputs and outputs in the interface.

### Fetcher
The fetcher is responsible for identifying which DVs are active, whether they should perform the duty in the slot and for
fetching input data required to perform the duty.

For `DutyAttester` it [fetches AttestationData](https://github.com/ethereum/beacon-APIs/blob/master/validator-flow.md#/ValidatorRequiredApi/produceAttestationData) from the beacon node.

For `DutyProposer` it fetches a previously aggregated randao_reveal from the `AggDB` and then [fetches a BeaconBlock object](https://github.com/ethereum/beacon-APIs/blob/master/validator-flow.md#/Validator/produceBlock)
from the beacon node.

An abstract `DutyData` type is defined to represent either `AttestationData` or `BeaconBlock` depending on the `DutyType`.
It contains the standard serialised json format of the data as returned from beacon node.

```go
// DutyData represents a duty data object.
type DutyData []byte
```

Since a cluster can contain multiple DVs, it may have to perform multiple similar `DutyAttester` duties for the same slot.
The fetcher therefore fetches multiple `DutyData` objects for the same `Duty`.


Multiple `DutyData`s are combined into a single `DutyDataSet` that is defined as:
```go
type DutyDataSet map[VIdx]DutyData
```
`DutyProposer` is however unique per slot, so its `DutyDataSet` will only ever contain a single entry.

DVs are identified by their validator index `VIdx` as any normal validator. It is obtained by querying the beacon node using the DV root public key.
```go
type VIdx int64
```
The duty data returned by a beacon node for a given slot is however not deterministic. It changes over and time and
from beacon node to beacon node. This means that different charon nodes will fetch different input data.
This is a problem since signing different data for the same duty results in slashing.

The fetcher therefore passes the `DutyDataSet` as a proposal to the `Consensus` component.

The fetcher interface is defined as:
```go
// Fetcher fetches proposed duty data.
type Fetcher interface {
  // Fetch triggers fetching of a proposed duty data set.
  Fetch(context.Context, types.Duty) error

  // Subscribe registers a callback for proposed duty data sets.
  Subscribe(func(context.Context, types.Duty, types.DutyDataSet) error)

  // RegisterAggDB registers a function to resolved aggregated
  // signatures from the AggDB (e.g., randao reveals).
  RegisterAggDB(func(context.Context, types.Duty, types.VIdx) (SignedDutyData, error))
}
```
### Consensus
The consensus component is responsible for coming to agreement on a duty's input data (`DutyDataSet`) between all nodes in the cluster.
This is achieved by playing a consensus game between all nodes in the cluster. This is critical for the following reasons:

- BLS threshold signature aggregation only works if the message that was signed is identical. So all nodes need to provide the exact same duty data to their VC for signing.
- Broadcasting different signed attestations/blocks to the beacon node is a slashable offence. Note that consensus isn’t sufficient to protect against this, a slashing DB is also required.

Consensus is similar to how some blockchains decide on what blocks define the chain. Popular protocols for consensus are raft, qbft, tendermint. Charon uses qbft for consensus.

The consensus requirements in DVT differs from blockchains in a few key aspects:
- Blockchains play consecutive consensus games that depend-on and follow-on the previous consensus game. Thereby creating a block “chain”.
- DVT plays single isolated consensus games.
- Blockchains play consensus games on blocks containing transactions.
- DVT plays consensus on arbitrary data, `DutyDataSet`

The consensus component participates qbft consensus games with other consensus components in the cluster leveraging libp2p for network
communication. A consensus game is either initiated by a duty data proposal received from the local node’s fetcher or from another
node's consensus component. When a consensus game completes, the resulting `DutyDataSet` is stored in the DutyDB.

The consensus component verifies that the `DutyDataSet` is valid during the consensus game.

The consensus interface is defined as:
```go
// Consensys comes to consensus on proposed duty data.
type Consensys interface {
	// Propose triggers consensus game of the proposed duty data set.
	Propose(context.Context, types.Duty, types.DutyDataSet) error

	// Subscribe registers a callback for resolved (reached consensus) duty data set.
	Subscribe(func(context.Context, types.Duty, types.DutyDataSet) error)
}
```

### DutyDB
The duty database persists agreed upon duty data sets and makes them available for querying.
It also acts as slashing database to aid in [avoiding slashing](https://github.com/ethereum/consensus-specs/blob/02b32100ed26c3c7a4a44f41b932437859487fd2/specs/phase0/validator.md#how-to-avoid-slashing) by applying unique indexes on the slot, duty type and DV.
ensuring a single unique `DutyData` per `Duty,VIdx`.

When receiving a `DutyDataSet` to store, it is split by `VIdx` and stored as separate entries in the database.
This ensures that a unique index can be applied on `Duty,VIdx`.

The data model for entries in this DB is defined as:
- *Key*: `ID int64` auto-incrementing primary-key.
- *Value*:
```go
type Entry struct {
  ID       int64
  Slot     int64
  DutyType byte
  VIdx     int64
  DutyData []byte
  CommIdx  int64   // committee index (0 for DutyProposer)
  AggBits  []byte  // aggregation bits (empty for DutyProposer)
}
```
> ℹ️ Database entry fields are persistence friendly types and are not exported or used outside this component

The database has the following indexes:
- `Slot,DutyType,VIdx`: unique index for deduplication and idempotent inserts
- `Slot,DutyType,CommIdx,AggBits`: Queried by `AwaitAttester` and `GetDVByAggBits`

The `DutyData` might however not be available yet at the time the VC queries the `ValidatorAPI`.
The `DutyDB` therefore provides a blocking query API. This query blocks until any requested data is available or until VC decides to timeout.

> 🏗️ TODO: Identify if it is safe to delete old entries.

The duty database interface is defined as:
```
// DutyDB persists duty data sets and makes it available for querying. It also acts
// as slashing database.
type DutyDB interface {
// Store stores the duty data set.
Store(context.Context, types.Duty, types.DutyDataSet) error

	// AwaitProposer blocks and returns the proposer duty data
	// for the slot when available. It also returns the DV.
	AwaitProposer(context.Context, types.Duty) (types.DutyData, types.VIdx, error)

	// AwaitProposer blocks and returns the attester duty data
	// for the slot and committee index when available.
	AwaitAttester(context.Context, types.Duty, int) (types.DutyData, error)

	// GetDVByAggBits returns the VIdx for the provided committee index
	// and aggregation bits hex. This allows mapping of attestation
	// data response to DV.
	GetDVByAggBits(context.Context, types.Duty, int, string) (types.VIdx, error)
}
```
### Validator API
The validator API provides a [beacon-node API](https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi) to downstream VCs,
intercepting some calls and proxying others directly to the upstream beacon node.
It mostly serves duty data requests from the `DutyDB` and sends the resulting signatures to the `SigDB`.

It provides the following beacon-node endpoints:

- `GET /eth/v1/validator/attestation_data` Produce an attestation data
  - The request arguments are: `slot` and `committee_index`
  - Query the `DutyDB` `AwaitAttester` with `DutyAttester`, `slot` and `committee_index`
- `GET /eth/v2/validator/blocks/{slot}` Produce a new block, without signature.
  - The request arguments are: `slot` and `randao_reveal`
  - Ignore `randao_reveal`
  - Query the `DutyDB` `AwaitProposer` with `DutyProposer` and `slot`
- `POST /eth/v1/beacon/pool/attestations` Submit Attestation objects to node
  - Construct a `SignedDutyData` for each attestation object in request body.
  - Infer `VIdx` of the request by querying the `DutyDB` `GetDVByAggBits` with the `slot`, `committee index` and `aggregation bits` provided in the request body.
  - Set the BLS private share `identifier` to charon node index.
  - Combine `SignedDutyData`s into a `SignedDutyDataSet`.
  - Store `SignedDutyDataSet` in the `SigDB`
- `POST /eth/v1/beacon/blocks` Publish a signed block
  - The request body contains `SignedBeaconBlock` object composed of `BeaconBlock` object (produced by beacon node) and validator signature.
  - Construct a `SignedDutyData` for the block object in request body.
  - Lookup `VIdx` by querying the `DutyDB` `AwaitProposer` with the slot in the request body.
  - Set the BLS private share `identifier` to charon node index.
  - Create a `SignedDutyDataSet` with only a single element.
  - Store `SignedDutyDataSet` in the `SigDB`

> 🏗️ TODO: Figure out other endpoints required.

### SigDB
The signature database persists partial BLS threshold signatures received internally (from the local Charon node's VC(s))
as well as externally (from other nodes in cluster).
It calls the `SigEx` component with signatures received internally to share them with all peers in the cluster.
When sufficient signatures have been received for a duty, it calls the `SigAgg` component.

Partial signatures in the database have one of the following states:

 - `Internal`: Received from local VC, not broadcasted yet.
 - `Broadcasted`: Received from peer, or broadcasted to peers.
 - `Aggregated`: Sent to `SigAgg` service.
 - `Expired`: Not eligible for aggregation anymore (too old).

The data model for entries in this DB is defined as:
 - *Key*: `ID int64` auto-incrementing primary-key.
 - *Value*:
```go
type Entry struct {
  CreatedAt int64 // Unix nano timestamp
  UpdatedAt int64 // Unix nano timestamp
  Slot      int64
  DutyType  byte
  VIdx      string
  DutyData  []byte
  Signature []byte
  Index     int32
  Status    byte
}
```
It has the following indexes:
 - `Slot,DutyType,VIdx,Index` a unique index on for idempotent inserts.
 - `Status/Slot/DutyType` for querying by state.

Entries inserted by `StoreInternal` have `Status=Interna`l, while entries inserted by `StoreExternal` have `Status=Broadcasted`.

A `broadcaster` worker goroutine, triggered periodically and by `StoreInternal` queries all `Status=Internal` entries,
sends them to `SigEX` as a batch, then updates them to `Status=Broadcasted` in a transaction.

An `aggregator` worker goroutine, triggered periodically and by `StoreExternal` and by `broadcaster`
queries all `Status=Broadcasted` entries, and if sufficient entries exist for a duty, sends them to the `SigAgg` component
and update them to `Status=Aggregated`. Entries older than `X?` epochs are set to `Status=Expired`.

> ⁉️ What about the race condition where some partial signatures are received AFTER others of the same duty reached threshold and was aggregated? Currently, they will Expire.

The signature database interface is defined as:
```go
// SigDB persists partial signatures and sends them for
// signature exchange and aggregation.
type SigDB interface {
  // StoreInternal stores an internally received partially signed duty data set.
  StoreInternal(context.Context, types.Duty, SignedDutyDataSet) error

  // StoreExternal stores an externally received partially signed duty data set.
  StoreExternal(context.Context, types.Duty, SignedDutyDataSet) error

  // SubscribeInternal registers a callback when an internal
  // partially signed duty set is stored.
  SubscribeInternal(func(context.Context, types.Duty, SignedDutyDataSet) error)

  // SubscribeThreshold registers a callback when *threshold*
  // partially signed duty is reached for a DV.
  SubscribeThreshold(func(context.Context, types.Duty, VIdx, []SignedDutyData) error)
}
```

### SigEx
The signature exchange component ensures that all partial signatures are persisted by all peers.
It registers with the `SigDB` for internally received partial signatures and broadcasts them in batches to all other peers.
It listens and receives batches of partial signatures from other peers and stores them in the `SigDB`.
It implements a simple libp2p protocol leveraging direct p2p connections to all nodes (instead of gossip-style pubsub).
This incurs higher network overhead (n^2), but improves aggregation latency.

The signature exchange interface is defined as:
```go
// SigEx exchanges partially signed duty data sets.
type SigEx interface {
  // Broadcast broadcasts the partially signed duty data set to all peers.
  Broadcast(context.Context, types.Duty, SignedDutyDataSet) error

  // Subscribe registers a callback when a partially signed duty set
  // is received from a peer.
  Subscribe(func(context.Context, types.Duty, SignedDutyDataSet) error)
}
```

### SigAgg
The signature aggregation service aggregates partial BLS signatures and sends them to the `bcast` component and persists them to the `AggDB`. It is a stateless pure function.

The signature aggregation interface is defined as:
```go

// SigAgg aggregates threshold partial signatures.
type SigAgg interface {
  // Aggregate aggregates the partially signed duty data for the DV.
  Aggregate(context.Context, types.Duty, VIdx, []SignedDutyData) error

  // Subscribe registers a callback for aggregated signatures and duty data.
  Subscribe(func(context.Context, types.Duty, VIdx, bls_sig.Signature, []byte) error)
}
```

### AggDB
The aggregate database persists aggregated BLS signatures and makes it available for querying.
This database persists the final end results of the duty workflow; aggregate signatures.
At this point, only `DutyRandao` is queried, but other use cases may yet present themselves.

The data model of the database is:
- Key: `fmt.Sprintf(Slot,"/",DutyType,"/",VIdx)`
- Value: `SignedDutyData` (without partial signature index)

> ⁉️ Can old data be trimmed/deleted and if so when?

The aggregate database interface is defined as:

```go
// AggDB persists aggregated signed duty data to the beacon node.
type AggDB interface {
  // Store stores aggregated signed duty data.
  Store(context.Context, types.Duty, types.VIdx, types.SignedDutyData) error

  // Get returns a set of aggregated signed duty data.
  Get(context.Context, types.Duty) (types.SignedDutyDataSet, error)
}
```
### Bcast
The broadcast component broadcasts aggregated signed duty data to the beacon node. It is a stateless pure function.

The broadcast interface is defined as:
```
// Bcast broadcasts aggregated signed duty data to the beacon node.
type Bcast interface {
  Broadcast(context.Context, types.Duty, types.VIdx, types.SignedDutyData) error
}
```
### Stitching the core workflow
The core workflow components are stitched together as follows:

```go
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
  aggDB AggDb,
  bcast Broadcaster,
) {
  sched.Subscribe(fetch.Fetch)
  fetch.Subscribe(cons.Propose)
  fetch.RegisterAgg(aggDB.Get)
  cons.Subscribe(dutyDB.Store)
  vapi.RegisterSource(dutyDB.Await)
  vapi.Subscribe(sigDB.StoreInternal)
  sigDB.SubscribeInternal(sigEx.Broadcast)
  sigEx.Subscribe(sigDB.StoreExternal)
  sigDB.SubscribeThreshold(sigAgg.Aggregate)
  sigAgg.Subscribe(aggDB.Store)
  sigAgg.Subscribe(bcast.Broadcast)
}
```
