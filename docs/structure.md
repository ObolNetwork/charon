# Charon Project Structure

This document outlines the project structure.

```
charon/                # project root
├─ main.go             # charon main package, it just calls cmd/
├─ cmd/                # command line interface, binary entrypoint, parses flags
│
├─ cluster/            # cluster config definition and file formats.
│
├─ dkg/                # distributed key generation command logic.
│
├─ app/                # application run entrypoint
│  ├─ app.go           # wires state and process lifecycle.
│  │
│  │                   # application infrastructure libraries
│  ├─ log/             # logging
│  ├─ errors/          # errors
│  ├─ z/               # structured logging and error fields (wraps zap fields)
│  ├─ tracer/          # tracing
│  ├─ version/         # app version
│  ├─ lifecycle/       # lifecycle manager
│  ├─ featureset/      # feature flags
│  ├─ eth2wrap/        # wrapper for the eth2 beacon node client (adds caching, metrics and error wrapping)
│  ├─ eth1wrap/        # execution layer (eth1) client wrapper
│  ├─ health/          # health checks
│  ├─ retry/           # async retry utilities
│  ├─ sse/             # beacon node server-sent events (head and chain reorg events)
│  ├─ obolapi/         # Obol API client
│  ├─ peerinfo/        # peer info exchange protocol
│  ├─ forkjoin/        # fork-join concurrency utilities
│  ├─ expbackoff/      # exponential backoff
│  ├─ promauto/        # prometheus metrics registration
│  ├─ k1util/          # secp256k1 utilities
│  ├─ privkeylock/     # private key file locking
│
├─ core/               # core workflow; charon business logic (see architecture doc for details)
│  ├─ interfaces.go    # component interfaces: Scheduler, Fetcher, Consensus, etc. Also Wire() stitching the workflow.
│  ├─ types.go         # core workflow types: Duty, PubKey, UnsignedData, SignedData, etc.
│  ├─ dutydefinition.go# DutyDefinition implementations
│  ├─ unsigneddata.go  # UnsignedData implementations and type safe encode/decode API
│  ├─ signeddata.go    # SignedData implementations and type safe encode/decode API
│  ├─ eth2signeddata.go# eth2 BLS signing/verification for SignedData types
│  ├─ ssz.go           # ssz serialisation of core types
│  ├─ proto.go         # protobuf serialisation of core types
│  ├─ deadline.go      # duty deadline/expiry logic (Deadliner)
│  ├─ gater.go         # duty gater, rejects invalid/expired duties from peers
│  ├─ tracing.go       # tracing wire option
│  ├─ tracking.go      # tracker/inclusion-checker wire option
│  ├─ corepb/          # core workflow protobufs
│  │
│  │                   # core workflow component implementations
│  ├─ scheduler/       # scheduler
│  ├─ fetcher/         # fetcher
│  ├─ consensus/       # consensus controller and protocol implementations (qbft)
│  ├─ qbft/            # generic qbft algorithm
│  ├─ dutydb/          # dutydb
│  ├─ validatorapi/    # validatorapi
│  ├─ parsigdb/        # parsigdb
│  ├─ parsigex/        # parsigex
│  ├─ sigagg/          # sigagg
│  ├─ aggsigdb/        # aggsigdb
│  ├─ bcast/           # broadcast
│  ├─ tracker/         # duty failure tracker and inclusion checker
│  ├─ priority/        # priority protocol, cluster wide preference negotiation
│  ├─ infosync/        # peer version/protocol info sync (uses priority protocol)
│
├─ p2p/                # p2p networking services
│  ├─ p2p.go           # libp2p tcp service, provides inter node communication
│  ├─ relay.go         # libp2p circuit relay reservations, peer discovery and routing
│  ├─ sender.go        # p2p message sending with retries
│  ├─ receive.go       # p2p protocol receive handlers
│  ├─ ping.go          # ping libp2p protocol
│
├─ tbls/               # bls threshold signature scheme; verify, aggregate partial signatures
│  ├─ tblsconv/        # bls threshold type conversion (tbls to/from core and eth2 types)
│
├─ eth2util/           # Ethereum consensus layer (ETH2) libraries and functionality
│  ├─ signing/         # ETH2 signature creation
│  ├─ deposit/         # ETH2 deposit data file creation
│  ├─ keystore/        # EIP 2335 keystore files
│  ├─ keymanager/      # keymanager API client
│  ├─ registration/    # builder registration creation
│  ├─ enr/             # Ethereum Node Records
│  ├─ eip712/          # EIP 712 typed data signing
│  ├─ rlp/             # RLP encoding
│
├─ testutil/           # testing libraries (unit, integration, simnet)
│  ├─ golden.go        # golden file testing
│  ├─ beaconmock/      # beacon client mock
│  ├─ validatormock/   # validator client mock
│  ├─ obolapimock/     # Obol API mock
│  ├─ relay/           # libp2p relay server (also run by charon relay command)
│  ├─ integration/     # integration tests
│  ├─ promrated/       # prometheus rated metrics service
│  ├─ verifypr/        # Github PR template verifier
│  ├─ genchangelog/    # Generate changelog markdown
│
├─ scripts/            # build and development scripts
├─ docs/               # Documentation
```

- `github.com/obolnetwork/charon`: Project root and main package
  - Contains `main.go` that just calls the [cobra](https://github.com/spf13/cobra) root command defined in `/cmd` package.
- `cmd/`: Command line interface
  - Defines cobra cli commands
    - `create`: Create artifacts for a distributed validator cluster
      - `cluster`: Create private keys and configuration files needed to run a distributed validator cluster locally
      - `enr`: Create an Ethereum Node Record (ENR) private key to identify this charon client
      - `dkg`: Create the configuration for a new Distributed Key Generation ceremony used by charon dkg
    - `dkg`: Participate in a Distributed Key Generation ceremony
    - `enr`: Prints ENR based on provided p2pkey and networking config
    - `relay`: Start a libp2p relay server
    - `run`: Runs the charon node
    - `version`: Print charon version
    - `combine`: Combine key shares of a cluster into the original validator keys
    - `exit`: Sign and broadcast validator exits (`sign`, `broadcast`, `fetch`, `delete`, `active-validator-list`)
    - `deposit`: Sign and fetch deposit data (`sign`, `fetch`)
    - `feerecipient`: Sign, fetch and list fee recipient changes (`sign`, `fetch`, `list`)
    - `alpha`: Early access to in-development features
      - `edit`: Edit an existing cluster (`add-validators`, `add-operators`, `remove-operators`, `replace-operator`, `recreate-private-keys`)
      - `test`: Test charon setup (`all`, `peers`, `beacon`, `validator`, `mev`, `infra`)
    - `unsafe run`: Runs the charon node with unsafe test options
  - Defines and parses [viper](https://github.com/spf13/viper) configuration parameters for required by each command.
- `cluster/`: Cluster config definition and files formats
  - `cluster-definition.json` defines the intended cluster including configuration including operators.
  - `cluster-lock.json` extends cluster definition adding distributed validator public keys and public shares.
- `dkg/`: Distributed Key Generation command
  - Runs the dkg command that takes a cluster definition as input and generates a cluster lock file and private shares as output.
- `app/`: Application run entrypoint
  - wires application state and process lifecycle.
  - Receives parsed config as input
  - Loads p2p private key from disk
  - Runs life cycle manager which starts processes and does graceful shutdown.
- `app/{subdirectory}/`: Application infrastructure libraries
  - Libraries that provide low level infrastructure level features and utilities. Avoid business logic and stateful services.
  - `log/`, `errors/`, `z/` provide structured logging and structured errors using [zap](https://github.com/uber-go/zap) fields
  - `tracer/` provides [open-telemetry](https://github.com/open-telemetry/opentelemetry-go) tracing (not metrics).
  - `version/` contains the global charon version
  - `lifecycle/` provide a process life cycle manager to `app/`.
  - `featureset/` manages feature flags used to gate new behaviour.
  - `eth2wrap/` wraps the beacon node client adding multi-node fallback, caching (validators, duties), metrics and error wrapping.
- `core/`: Core workflow, the charon business logic
  - See the [architecture](architecture.md) document for details on the core workflow.
  - `interfaces.go`, `types.go` defines the core workflow interfaces and types.
  - `dutydefinition.go`, `unsigneddata.go`, `signeddata.go`, `ssz.go`, `proto.go` provide the concrete
    implementations of the abstract core types with type safe encode/decode functions (json, ssz, protobuf).
- `core/{subdirectory}`: Core workflow components
  - See the [architecture](architecture.md) document for details on the core workflow.
  - Each component defined in its own package.
  - Implements a core workflow interface using core workflow types.
  - `consensus/` contains the consensus controller and protocol implementations (see [consensus.md](consensus.md));
    `qbft/` contains the generic QBFT algorithm it builds on.
  - `tracker/`, `priority/` and `infosync/` are supporting components (duty failure tracking,
    cluster wide preference negotiation and peer version sync).
- `p2p/`: p2p networking services
  - Provides networking services to the core workflow.
  - Uses p2p private key for authentication
  - `p2p.go`: [libp2p](https://github.com/libp2p/go-libp2p) used for inter-node communication.
  - `relay.go`: Peer discovery and routing via [libp2p circuit relay](https://docs.libp2p.io/concepts/nat/circuit-relay/) servers.
- `tbls/`: BLS Threshold Signature Scheme
  - Supports validating individual partial signatures received from VC.
  - Supports aggregating partial signatures.
  - Support generating scheme and private shares for testing (done by DKG in prod).
- `eth2util/`: Ethereum consensus layer (ETH2) libraries and functionality
  - `signing/`: ETH2 signature creation including domain and data structures.
  - `deposit/`: ETH2 deposit data file creation
  - `keystore/`: EIP 2335 keystore files
  - `registration/`: Builder (pre-signed) validator registration creation
- `testutil/`: Test utilities
  - `beaconmock/`: Beacon-node client mock used for testing and simnet.
  - `validatormock/`: Validator client mock used for testing and simnet.
  - `relay/`: The libp2p relay server, also run by the `charon relay` command.

The package import hierarchy can be illustrated as follows:
```


                  ┌──────┐
                  │ main │
                  └──┬───┘
                     │                                           app/*
                  ┌──▼───┐       ┌──────┐                  ┌───────────────┐
                  │ cmd  ├───────► dkg  ├───────┬──────────► ┌─────────┐   │
                  └──┬───┘       └────┬─┘       │          │ │ version │   │
                     │                │         │          │ └─────────┘   │
                  ┌──▼───┐            │    ┌────▼────┐     │ ┌─────────┐   │
                  │ app  ├─────────────────► cluster ├─────► │    z    ◄─┐ │
   core/*         └─┬──┬─┘            │    └─────────┘     │ └─▲───────┘ │ │
  ┌──────┐          │  │              │                    │ ┌─┴───────┐ │ │
  │sched │◄──────┬──┘  └─────┬────────┤                    │ │ errors  ◄─┤ │
  ├──────┤       │           │        │                    │ └─────────┘ │ │
  │fetch │    ┌──▼───┐       │        │                    │ ┌─────────┐ │ │
  ├──────┼────► core ├───────┼────────┼────────┬───────────► │  log    ◄─► │
  │dutydb│    └──────┘       │        │        │           │ └─────────┘ │ │
  ├──────┤              ┌────▼───┐    │        │           │ ┌─────────┐ │ │
  │...   ├──────────────►  tbls  ├─────────────────────────► │ tracer  ├─┤ │
  ├──────┼              ├────▲───┤  ┌─▼─┐      │           │ └─────────┘ │ │
  │sigagg│              │tblsconv│  │p2p├──────────────────► ┌─────────┐ │ │
  ├──────┤              └────────┘  └─▲─┘ ┌────▼───────┐   │ │lifecycle├─┘ │
  │bcast │                            │   │ eth2util/* ├── ► └─────────┘   │
  └──┬───┘                            │   └────▲───────┘   └──────▲────────┘
     │                                │        │                  │
     └────────────────────────────────┴────────┴──────────────────┘

```
