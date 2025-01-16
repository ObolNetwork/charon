# Charon Project Structure

This document outlines the project structure.

```
charon/             # project root
├─ main.go          # charon main package, it just calls cmd/
├─ cmd/             # command line interface, binary entrypoint, parses flags
│
├─ cluster/         # cluster config definition and file formats.
│
├─ dkg/             # distributed key generation command logic.
│
├─ app/             # application run entrypoint
│  ├─ app.go        # wires state and process lifecycle.
│  │
│  │                # application infrastructure libraries
│  ├─ log/          # logging
│  ├─ errors/       # errors
│  ├─ z/            # structured logging and error fields (wraps zap fields)
│  ├─ tracer/       # tracing
│  ├─ version/      # app version
│  ├─ lifecycle/    # lifecycle manager
│  ├─ dbindex/      # badger DB index helper
│  ├─ eth2wrap/     # wrapper for eth2http beacon node client (adds metrics and error wrapping)
│
├─ core/            # core workflow; charon business logic (see architecture doc for details)
│  ├─ interfaces.go # component interfaces: Scheduler, Fetcher, Consensus, etc.
│  ├─ types.go      # core workflow types: Duty, PubKey, DutyDefinition, UnsignedData, etc.
│  ├─ encode.go     # encode/decode the abstract types with type safe API
│  │
│  │                # core workflow component implementations
│  ├─ scheduler/    # scheduler
│  ├─ fetcher/      # fetcher
│  ├─ dutydb/       # dutydb
│  ├─ validatorapi/ # validatorapi
│  ├─ parsigdb/     # parsigdb
│  ├─ parsigex/     # parsigex
│  ├─ sigagg/       # sigagg
│  ├─ aggsigdb/     # aggsigdb
│  ├─ bcast/        # broadcast
│
├─ p2p/             # p2p networking services
│  ├─ p2p.go        # libp2p tcp service, provides inter node communication
│  ├─ discovery.go  # discv5 udp service, peer discovery for libp2p.
│  ├─ ping.go       # ping libp2p protocol
│
├─ tbls/            # bls threshold signature scheme; verify, aggregate partial signatures
│  ├─ tblsconv/     # bls threshold type conversion (tbls to/from core and eth2 types)
│
├─ eth2util/        # Ethereum consensus layer (ETH2) libraries and functionality
│  ├─ signing/      # ETH2 signature creation
│  ├─ deposit/      # ETH2 deposit data file creation
│  ├─ keystore/     # EIP 2335 keystore files
│
├─ testutil/        # testing libraries (unit, integration, simnet)
│  ├─ golden.go     # golden file testing
│  ├─ beaconmock/   # beacon client mock
│  ├─ validatormock/# validator client mock
│  ├─ verifypr/     # Github PR template verifier
│  ├─ genchangelog/ # Generate changelog markdown
│
├─ docs/            # Documentation
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
  - `dbindex/` provides an opinionated [BadgerDB](https://github.com/dgraph-io/badger) index library leveraging [roaring bitmaps](https://github.com/dgraph-io/sroar).
- `core/`: Core workflow, the charon business logic
  - See the [architecture](architecture.md) document for details on the core workflow.
  - `interfaces.go`, `types.go` defines the core workflow interfaces and types.
  - `encode.go` provides type safe encode/decode functions to/from concrete implementation types from/to abstract types.
- `core/{subdirectory}`: Core workflow components
  - See the [architecture](architecture.md) document for details on the core workflow.
  - Each component defined in its own package.
  - Implements a core workflow interface using core workflow types.
- `p2p/`: p2p networking services
  - Provides networking services to the core workflow.
  - Uses p2p private key for authentication
  - `p2p.go`: [libp2p](https://github.com/libp2p/go-libp2p) used for inter-node communication.
  - `discovery.go`: Uses [geth's](https://github.com/ethereum/go-ethereum/tree/master/p2p/discover) [discv5](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md) implementation for service discovery and routing to libp2p.
- `tlbs/`: BLS Threshold Signature Scheme
  - Supports validating individual partial signatures received from VC.
  - Supports aggregating partial signatures.
  - Support generating scheme and private shares for testing (done by DKG in prod).
- `eth2util/`: Ethereum consensus layer (ETH2) libraries and functionality
  - `signing/`: ETH2 signature creation including domain and data structures.
  - `deposit/`: ETH2 deposit data file creation
  - `keystore/`: EIP 2335 keystore files
- `testutil/`: Test utilities
  - `beaconmock/`: Beacon-node client mock used for testing and simnet.
  - `validatormock/`: Validator client mock used for testing and simnet.

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
