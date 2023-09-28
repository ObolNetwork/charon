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

      Phases │ Components                              │ External
─────────────┴─────────────────────────────────────────┴──────────────────────

             │                ┌─────────┐
  *Schedule* │          ┌─────◆Scheduler│
        duty │          |     └─&┌──────┘
                        |        │
             │          |     ┌──▼────┐
             │  ┌──----------─┤Fetcher│
             │  │       |     └─&┌────┘
    *Decide* │  |       |        │
        what │  |       |     ┌──▼──────┐
        data │  |       |     │Consensus│
          to │  |       |     └─*┌──────┘
        sign │  |       |        ├────────────┐
             │  |       |     ┌──▼───┐     ┌──▼───┐    │
             │  |       |     │DutyDB│     │Signer├────│─► RS
             │  |       |     └──◆───┘     └──┬───┘    │ Remote signer
                |       |        │            │        │
      *Sign* │  |       |     ┌──┴─┐          │        │
        duty │  |       └----─┤VAPI◄───────────────────│── VC
        data │  |             └──┬─┘          │        │ Query, sign, submit
                |                ├────────────┘        │
     *Share* │  | ┌────────┐  ┌──▼─────┐
     partial │  | │ParSigEx◄──►ParSigDB│
        sigs │  | └─────*──┘  └──┬─────┘
                |                │
 *Aggregate* │  │ ┌────────┐  ┌──▼───┐
     partial │  └─◆AggSigDB◄──┤SigAgg│
        sigs │    └────────┘  └──┬───┘
                                 │
 *Broadcast* │                ┌──▼──────┐
  aggregated │                │Broadcast│
         sig │                └─&───────┘

       &: Beacon-node client calls
       *: P2P protocol
       ▼: Pushed data (in direction of the arrow)
       ◆: Pulled data (returned from the diamond)
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
// Duty is the unit of work of the core workflow.
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
- `DutyExit = 4`: Voluntary exit
- `DutyBuilderProposer = 5`: Proposing a blinded block received from the builder network
- `DutyBuilderRegistration = 6`: Registering a validator to the builder network

> ℹ️ Duty is on a cluster level, not a DV level. A duty defines the “unit of work” for the whole cluster,
> not just a single DV. This allows the workflow to aggregate and batch multiple DVs in some steps, specifically consensus.
> Which is critical for clusters with a large number of DVs.

### Scheduler

The scheduler is the initiator of a duty in the core workflow. It resolves the which DVs in the cluster are active and
is then responsible for starting a duty at the optimal time by calling the `fetcher`.

DVs are identified by their root public key `PubKey`.
```go
// PubKey is the DV root public key, the identifier of a validator in the core workflow.
// It is a hex formatted string, e.g. "0xb82bc6...."
type PubKey string
```
It has access to validators in cluster-lock, so it first resolves validator status for each
DV by calling [Get validator from state by id](https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi/getStateValidator)
using `HEAD` state and the DV root public key.

If the validator is not found or is not active, it is skipped.

It then calls [Get attester duties](https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi/getAttesterDuties)
and [Get block proposer](https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi/getProposerDuties) duties on the beacon API
at the end of each epoch for the next epoch. It then caches the results returned and triggers the duty
when the associated slot starts.

An abstract `DutyDefinition` type is defined that represents the json formatted responses returned by the beacon node above.
Note the ETH2 spec refers to these as "duties", but we use a slightly different term to avoid overloading
the term "duty" which we defined above.
```go
// DutyDefinition defines a duty including parameters required
// to fetch the duty data, it is the result of resolving duties
// at the start of an epoch.
type DutyDefinition interface {
  // Clone returns a cloned copy of the DutyDefinition.
  Clone() (DutyDefinition, error)
  // Marshaler returns the json serialised duty definition.
  json.Marshaler
}
```

The following `DutyDefinition` implementations are provided:
 - `AttesterDefinition` which wraps "Get attester duties" response above.
 - `ProposerDefinition` which wraps "Get block proposer" response above.

Since a cluster can contain multiple DVs, it may have to perform multiple similar duties for the same slot, e.g. `DutyAttester`.
Multiple `DutyDefinition`s are combined into a single `DutyDefinitionSet` that is defined as:
```go
// DutyDefinitionSet is a set of fetch args, one per validator.
type DutyDefinitionSet map[PubKey]DutyDefinition
```

Note the `DutyRandao`, `DutyExit` & `DutyBuilderRegistration` isn’t scheduled by the scheduler, since they are initiated directly by VC.

> ℹ️ The core workflow follows the immutable architecture approach, with immutable self-contained values flowing between components.
> Values can be thought of as events or messages and components can be thought of as actors consuming and generating events.
> This however requires that values are immutable. All abstract value types therefore define a `Clone` method
> that must be called before a value leaves its scope (shared, cached, returned etc.).

> 🏗️ TODO: Define the exact timing requirements for different duties.

The scheduler interface is defined as:
```go
// Scheduler triggers the start of a duty workflow.
type Scheduler interface {
  // Subscribe registers a callback for triggering a duty.
  Subscribe(func(context.Context, Duty, DutyDefinitionSet) error)

  // GetDutyDefinition returns the definition for a duty if already resolved.
  GetDutyDefinition(context.Context, Duty) (DutyDefinitionSet, error)
}
```
> ℹ️ Components of the workflow are decoupled from each other. They are stitched together by callback subscriptions.
> This improves testability and avoids the need for mocks. It also allows defining both inputs and outputs in the interface.
> It also allows for cyclic dependencies between components.

### Fetcher
The fetcher is responsible for fetching input data required to perform the duty. It is a stateless pure function.

For `DutyAttester` it [fetches AttestationData](https://github.com/ethereum/beacon-APIs/blob/master/validator-flow.md#/ValidatorRequiredApi/produceAttestationData) from the beacon node.

For `DutyProposer` it fetches a previously aggregated randao_reveal from the `AggSigDB` and then [fetches a BeaconBlock object](https://github.com/ethereum/beacon-APIs/blob/master/validator-flow.md#/Validator/produceBlock)
from the beacon node.

An abstract `UnsignedData` type is defined to represent either `AttestationData` or `BeaconBlock` depending on the `DutyType`.

```go
// UnsignedData represents an unsigned duty data object.
type UnsignedData interface {
  // Clone returns a cloned copy of the UnsignedData.
  Clone() (UnsignedData, error)
  // Marshaler returns the json serialised unsigned duty data.
  json.Marshaler
}
```

Since the input to fetcher is a `DutyDefinitionSet`, it fetches multiple `UnsignedData` objects for the same `Duty`.
Multiple `UnsignedData`s are combined into a single `UnsignedDataSet` that is defined as:
```go
// UnsignedDataSet is a set of unsigned duty data objects, one per validator.
type UnsignedDataSet map[PubKey]UnsignedData
```
`DutyProposer` is however unique per slot, so its `UnsignedDataSet` will only ever contain a single entry.

The unsigned duty data returned by a beacon node for a given slot is however not deterministic. It changes over and time and
from beacon node to beacon node. This means that different charon nodes will fetch different input data.
This is a problem since signing different data for the same duty results in slashing.

The fetcher therefore passes the `UnsignedDataSet` as a proposal to the `Consensus` component.

The fetcher interface is defined as:
```go
// Fetcher fetches proposed duty data.
type Fetcher interface {
  // Fetch triggers fetching of a proposed duty data set.
  Fetch(context.Context, Duty, DutyDefinitionSet) error

  // Subscribe registers a callback for proposed duty data sets.
  Subscribe(func(context.Context, Duty, UnsignedDataSet) error)

  // RegisterAggSigDB registers a function to resolved aggregated
  // signed data from the AggSigDB (e.g., randao reveals).
  RegisterAggSigDB(func(context.Context, Duty, PubKey) (SignedData, error))
}
```
### Consensus
The consensus component is responsible for coming to agreement on a duty's input data (`UnsignedDataSet`) between all nodes in the cluster.
This is achieved by playing a consensus game between all nodes in the cluster. This is critical for the following reasons:

- BLS threshold signature aggregation only works if the message that was signed is identical. So all nodes need to provide the exact same duty data to their VC for signing.
- Broadcasting different signed attestations/blocks to the beacon node is a slashable offence. Note that consensus isn’t sufficient to protect against this, a slashing DB is also required.

Consensus is similar to how some blockchains decide on what blocks define the chain. Popular protocols for consensus are raft, qbft, tendermint. Charon uses qbft for consensus.

The consensus requirements in DVT differs from blockchains in a few key aspects:
- Blockchains play consecutive consensus games that depend-on and follow-on the previous consensus game. Thereby creating a block “chain”.
- DVT plays single isolated consensus games.
- Blockchains play consensus games on blocks containing transactions.
- DVT plays consensus on arbitrary data, `UnsignedDataSet`

The consensus component participates qbft consensus games with other consensus components in the cluster leveraging libp2p for network
communication. A consensus game is either initiated by a duty data proposal received from the local node’s fetcher or from another
node's consensus component. When a consensus game completes, the resulting `UnsignedDataSet` is stored in the DutyDB.

The consensus component verifies that the `UnsignedDataSet` is valid during the consensus game.

The consensus interface is defined as:
```go
// Consensus comes to consensus on proposed duty data.
type Consensus interface {
	// Propose triggers consensus game of the proposed duty unsigned data set.
	Propose(context.Context, Duty, UnsignedDataSet) error

	// Subscribe registers a callback for resolved (reached consensus) duty unsigned data set.
	Subscribe(func(context.Context, Duty, UnsignedDataSet) error)
}
```

### DutyDB
The duty database persists agreed upon unsigned data sets and makes them available for querying.
It also acts as slashing database to aid in [avoiding slashing](https://github.com/ethereum/consensus-specs/blob/02b32100ed26c3c7a4a44f41b932437859487fd2/specs/phase0/validator.md#how-to-avoid-slashing) by applying unique indexes on the slot, duty type and DV.
ensuring a single unique `UnsignedData` per `Duty,PubKey`.

When receiving a `UnsignedDataSet` to store, it is split by `PubKey` and stored as separate entries in the database.
This ensures that a unique index can be applied on `Duty,PubKey`.

The data model for entries in this DB is defined as:
- *Key*: `ID int64` auto-incrementing primary-key.
- *Value*:
```go
type Entry struct {
  ID           int64
  Slot         int64
  DutyType     byte
  PubKey       string
  Data         []byte  // unsigned data object
  CommIdx      int64   // committee index (0 for DutyProposer)
  ValCommIdx   int64   // validator committee index (0 for DutyProposer)
}
```
> ℹ️ Database entry fields are persistence friendly types and are not exported or used outside this component

The database has the following indexes:
- `Slot,DutyType,PubKey`: unique index for deduplication and idempotent inserts
- `Slot,DutyType,CommIdx,ValCommIdx`: Queried by `AwaitAttester` and `PubKeyByAttestation`

The `UnsignedData` might however not be available yet at the time the VC queries the `ValidatorAPI`.
The `DutyDB` therefore provides a blocking query API. This query blocks until any requested data is available or until VC decides to timeout.

> 🏗️ TODO: Identify if it is safe to delete old entries.

The duty database interface is defined as:
```go
// DutyDB persists unsigned duty data sets and makes it available for querying. It also acts
// as slashing database.
type DutyDB interface {
        // Store stores the unsigned duty data set.
        Store(context.Context, Duty, UnsignedDataSet) error

        // AwaitBeaconBlock blocks and returns the proposed beacon block
        // for the slot when available. It also returns the DV public key.
        AwaitBeaconBlock(context.Context, slot int) (PubKey, beaconapi.BeaconBlock, error)

        // AwaitBlindedBeaconBlock blocks and returns the proposed blinded beacon block
        // for the slot when available. It also returns the DV public key.
        AwaitBlindedBeaconBlock(context.Context, slot int) (PubKey, beaconapi.BlindedBeaconBlock, error)

        // AwaitAttestation blocks and returns the attestation data
        // for the slot and committee index when available.
        AwaitAttestation(context.Context, slot int, commIdx int) (*beaconapi.AttestationData, error)

        // PubKeyByAttestation returns the validator PubKey for the provided attestation data
        // slot, committee index and validator committee index. This allows mapping of attestation
        // data response to validator.
        PubKeyByAttestation(context.Context, slot int, commIdx int, valCommIdx int) (PubKey, error)
}
```
### Validator API
The validator API provides a [beacon-node API](https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi) to downstream VCs,
intercepting some calls and proxying others directly to the upstream beacon node.
It mostly serves unsigned duty data requests from the `DutyDB` and sends the resulting partial signed duty objects to the `ParSigDB`.

Partial signed duty data values are defined as `ParSignedData` which extend `SignedData` values:
```go
// SignedData is a signed duty data.
type SignedData interface {
  // Signature returns the signed duty data's signature.
  Signature() Signature
  // SetSignature returns a copy of signed duty data with the signature replaced.
  SetSignature(Signature) (SignedData, error)
  // Clone returns a cloned copy of the SignedData.
  Clone() (SignedData, error)
  // Marshaler returns the json serialised signed duty data (including the signature).
  json.Marshaler
}

// ParSignedData is a partially signed duty data only signed by a single threshold BLS share.
type ParSignedData struct {
  // SignedData is a partially signed duty data.
  SignedData
  // ShareIdx returns the threshold BLS share index.
  ShareIdx int
}

```

The following `SignedData` implementations are provided: `Attestation`, `VersionedSignedBeaconBlock`, `VersionedSignedBlindedBeaconBlock`, `SignedVoluntaryExit`, `VersionedSignedValidatorRegistration` and `SignedRandao` which is used for `DutyRandao`.

Multiple `ParSignedData` are combined into a single `ParSignedDataSet` defines as follows:
```go
// ParSignedDataSet is a set of partially signed duty data objects, one per validator.
type ParSignedDataSet map[PubKey]ParSignedData
```

The validator API provides the following beacon-node endpoints relating to duties:

- `GET /eth/v1/validator/attestation_data` Produce an attestation data
  - The request arguments are: `slot` and `committee_index`
  - Query the `DutyDB` `AwaitAttester` with `slot` and `committee_index`
  - Serve response
- `GET /eth/v2/validator/blocks/{slot}` Produce a new block, without signature.
  - The request arguments are: `slot` and `randao_reveal`
  - Lookup `PubKey` by querying the `Scheduler` `AwaitProposer` with the slot in the request body.
  - Verify `randao_reveal` signature.
  - Construct a `DutyRandao` `ParSignedData` and submit it to `ParSigDB` for async aggregation and inclusion in block consensus.
  - Query the `DutyDB` `AwaitBeaconBlock` with the `slot`
  - Serve response
- `GET /eth/v1/validator/blinded_blocks/{slot}` Produce a new blinded block, without signature.
  - The request arguments are: `slot` and `randao_reveal`
  - Lookup `PubKey` by querying the `Scheduler` `AwaitBuilderProposer` with the slot in the request body.
  - Verify `randao_reveal` signature.
  - Construct a `DutyRandao` `ParSignedData` and submit it to `ParSigDB` for async aggregation and inclusion in block consensus.
  - Query the `DutyDB` `AwaitBlindedBeaconBlock` with the `slot`
  - Serve response
- `POST /eth/v1/beacon/pool/attestations` Submit Attestation objects to node
  - Construct a `ParSignedData` for each attestation object in request body.
  - Infer `PubKey` of the request by querying the `DutyDB` `PubKeyByAttestation` with the `slot`, `committee index` and `aggregation bits` provided in the request body.
  - Set the BLS private share `index` to charon node index.
  - Combine `ParSignedData`s into a `SignedDutyDataSet`.
  - Store `SignedDutyDataSet` in the `SigDB`
- `POST /eth/v2/beacon/blocks` Publish a signed block
  - The request body contains `SignedBeaconBlock` object composed of `BeaconBlock` object (produced by beacon node) and validator signature.
  - Lookup `PubKey` by querying the `Scheduler` `AwaitProposer` with the slot in the request body.
  - Construct a `DutyProposer` `ParSignedData` and submit it to `ParSigDB` for async aggregation and broadcast to beacon node.
- `POST /eth/v1/beacon/blinded_blocks` Publish a signed blinded block
  - The request body contains `SignedBlindedBeaconBlock` object composed of `BlindedBeaconBlock` object (produced by beacon node) and validator signature.
  - Lookup `PubKey` by querying the `Scheduler` `AwaitBuilderProposer` with the slot in the request body.
  - Construct a `DutyBuilderProposer` `ParSignedData` and submit it to `ParSigDB` for async aggregation and broadcast to beacon node.

`AwaitBeaconBlock` returns an agreed-upon (consensus) unsigned beacon block, which in turn requires
an aggregated randao reveal signature. Partial randao reveal signatures are submitted at the same time as
unsigned beacon block is requested. `getDutyFunc` returns the duty data corresponding to the duty provided and can be obtained directly from the `Scheduler`.

Note that the VC is configured with one or more private key shares (output of the DKG).
The VC infers its public keys from those private shares, but those public keys does not exist on the beacon chain.
The validatorapi therefore needs to intercept and map all endpoints containing the validator public key and map
the public share (what the VC thinks as its public key) to and from the DV root public key.

> 🏗️ TODO: Figure out other endpoints required.

The validator api interface is defined as:
```go
// ValidatorAPI provides a beacon node API to validator clients. It serves duty data from the
// DutyDB and stores partial signed data in the ParSigDB.
type ValidatorAPI interface {
        // RegisterAwaitBeaconBlock registers a function to query a unsigned beacon block by slot.
        RegisterAwaitBeaconBlock(func(context.Context, slot int) (beaconapi.BeaconBlock, error))

        // RegisterAwaitBlindedBeaconBlock registers a function to query a unsigned blinded beacon block by slot.
        RegisterAwaitBlindedBeaconBlock(func(context.Context, slot int) (beaconapi.BlindedBeaconBlock, error))

        // RegisterGetDutyFunc registers a function to query duty data.
        RegisterGetDutyFunc(func(ctx context.Context, duty Duty) (DutyDefinitionSet, error))

        // RegisterAwaitAttestation registers a function to query attestation data.
        RegisterAwaitAttestation(func(context.Context, slot int, commIdx int) (*beaconapi.AttestationData, error))

        // RegisterPubKeyByAttestation registers a function to query validator by attestation.
        RegisterPubKeyByAttestation(func(context.Context, slot int, commIdx int, valCommIdx int) (PubKey, error))

        // RegisterParSigDB registers a function to store partially signed data sets.
        RegisterParSigDB(func(context.Context, Duty, ParSignedDataSet) error)
}
```

### Signer
The signer provides support the alternative _Remote Signature_ architecture
which authorises charon to request adhoc signatures from a [remote signer instance](https://lighthouse-book.sigmaprime.io/validator-web3signer.html).
In the _middleware_ architecture charon cannot initiate signatures itself and has to
wait for the VC to submit signatures.

Duties originating in the `scheduler` (`DutyAttester`, `DutyProposer`, `DutyBuilderProposer`) are not significantly affected by this change in architecture.
Instead of waiting for the `validatorapi` to submit signatures, these duties directly request
signatures from the remote signer instance. The flow is otherwise unaffected.

Duties originating in the `validatorapi` (`DutyRandao`, `DutyExit`, `DutyBuilderRegistration`) has to refactored to
originate in the `scheduler`, since charon is in full control of the duties in this architecture.

The overall core workflow remains the same, `scheduler` just schedules all the duties.

> 🏗️ TODO: Figure out if signer should query DutyDB for slashing, or if DutyDB should push to signer.

```go
// Signer signs unsigned duty data sets via one or more remote signer instances.
type Signer interface {
    // Sign signs the unsigned duty data set.
    Sign(context.Context, Duty, UnsignedDataSet) error

    // RegisterParSigDB registers a function to store partially signed data sets.
    RegisterParSigDB(func(context.Context, Duty, ParSignedDataSet) error))
}
```

### ParSigDB
The partial signature database persists partial BLS threshold signatures received internally (from the local Charon node's VC(s))
as well as externally (from other nodes in cluster).
It calls the `ParSigEx` component with signatures received internally to share them with all peers in the cluster.
When sufficient partial signatures have been received for a duty, it calls the `SigAgg` component.

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
  PubKey    string
  Data      []byte // Partially signed data object
  Signature []byte
  Index     int32
  Status    byte
}
```
It has the following indexes:
 - `Slot,DutyType,PubKey,Index` a unique index on for idempotent inserts.
 - `Status,Slot,DutyType` for querying by state.

Entries inserted by `StoreInternal` have `Status=Internal`, while entries inserted by `StoreExternal` have `Status=Broadcasted`.

A `broadcaster` worker goroutine, triggered periodically and by `StoreInternal` queries all `Status=Internal` entries,
sends them to `ParSigEX` as a batch, then updates them to `Status=Broadcasted` in a transaction.

An `aggregator` worker goroutine, triggered periodically and by `StoreExternal` and by `broadcaster`
queries all `Status=Broadcasted` entries, and if sufficient entries exist for a duty, sends them to the `SigAgg` component
and update them to `Status=Aggregated`. Entries older than `X?` epochs are set to `Status=Expired`.

> ⁉️ What about the race condition where some partial signatures are received AFTER others of the same duty reached threshold and was aggregated? Currently, they will Expire.

The partial signature database interface is defined as:
```go
// ParSigDB persists partial signatures and sends them to the
// partial signature exchange and aggregation.
type ParSigDB interface {
  // StoreInternal stores an internally received partially signed duty data set.
  StoreInternal(context.Context, Duty, ParSignedDataSet) error

  // StoreExternal stores an externally received partially signed duty data set.
  StoreExternal(context.Context, Duty, ParSignedDataSet) error

  // SubscribeInternal registers a callback when an internal
  // partially signed duty set is stored.
  SubscribeInternal(func(context.Context, Duty, ParSignedDataSet) error)

  // SubscribeThreshold registers a callback when *threshold*
  // partially signed duty is reached for a DV.
  SubscribeThreshold(func(context.Context, Duty, PubKey, []ParSignedData) error)
}
```

### ParSigEx
The partial signature exchange component ensures that all partial signatures are persisted by all peers.
It registers with the `ParSigDB` for internally received partial signatures and broadcasts them in batches to all other peers.
It listens and receives batches of partial signatures from other peers and stores them back to the `ParSigDB`.
It implements a simple libp2p protocol leveraging direct p2p connections to all nodes (instead of gossip-style pubsub).
This incurs higher network overhead (n^2), but improves latency.

The partial signature exchange interface is defined as:
```go
// ParSigEx exchanges partially signed duty data sets.
type ParSigEx interface {
  // Broadcast broadcasts the partially signed duty data set to all peers.
  Broadcast(context.Context, Duty, ParSignedDataSet) error

  // Subscribe registers a callback when a partially signed duty set
  // is received from a peer.
  Subscribe(func(context.Context, Duty, ParSignedDataSet) error)
}
```

### SigAgg
The signature aggregation service aggregates partial BLS signatures and sends them to the `bcast` component and persists them to the `AggSigDB`.
It is a stateless pure function.

Aggregated signed duty data objects are defined as `SignedData` defined above.

The signature aggregation interface is defined as:
```go

// SigAgg aggregates threshold partial signatures.
type SigAgg interface {
  // Aggregate aggregates the partially signed duty data for the DV.
  Aggregate(context.Context, Duty, PubKey, []ParSignedData) error

  // Subscribe registers a callback for aggregated signed duty data.
  Subscribe(func(context.Context, Duty, PubKey, SignedData) error)
}
```

### AggSigDB
The aggregated signature database persists aggregated signed duty data and makes it available for querying.
This database persists the final results of the core workflow; aggregate signatures.
At this point, only `DutyRandao` is queried, but other use cases may yet present themselves.

The data model of the database is:
- Key: `Slot,DutyType,PubKey`
- Value: `SignedData`

> ⁉️ When can old data be trimmed/deleted?

The aggregated signature database interface is defined as:
```go
// AggSigDB persists aggregated signed duty data.
type AggSigDB interface {
  // Store stores aggregated signed duty data.
  Store(context.Context, Duty, PubKey, SignedData) error

  // Await blocks and returns the aggregated signed duty data when available.
  Await(context.Context, Duty, PubKey) (SignedData, error)
}
```
### Bcast
The broadcast component broadcasts aggregated signed duty data to the beacon node. It is a stateless pure function.

The broadcast interface is defined as:
```go
// Bcast broadcasts aggregated signed duty data to the beacon node.
type Bcast interface {
  Broadcast(context.Context, Duty, PubKey, SignedData) error
}
```
### Stitching the core workflow
The core workflow components are stitched together as follows:

```go
// StitchFlow stitches the workflow steps together.
func StitchFlow(
  sched    Scheduler,
  fetch    Fetcher,
  cons     Consensus,
  dutyDB   DutyDB,
  vapi     ValidatorAPI,
  signer   Signer,
  parSigDB ParSigDB,
  parSigEx ParSigEx,
  sigAgg   SigAgg,
  aggSigDB AggSigDB,
  bcast    Broadcaster,
) {
  sched.Subscribe(fetch.Fetch)
  fetch.Subscribe(cons.Propose)
  fetch.RegisterAgg(aggSigDB.Get)
  cons.Subscribe(dutyDB.Store)
  vapi.RegisterSource(dutyDB.Await)
  vapi.Subscribe(parSigDB.StoreInternal)
  cons.Subscribe(signer.Sign)
  signer.Subscribe(parSigDB.StoreInternal)
  parSigDB.SubscribeInternal(parSigEx.Broadcast)
  parSigEx.Subscribe(parSigDB.StoreExternal)
  parSigDB.SubscribeThreshold(sigAgg.Aggregate)
  sigAgg.Subscribe(aggSigDB.Store)
  sigAgg.Subscribe(bcast.Broadcast)
}
```
