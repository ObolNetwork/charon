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
