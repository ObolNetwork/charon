# Charon Project Structure

This document outlines the project structure.

```
charon/             # project root
├─ main.go          # charon main package, it just calls cmd/
├─ cmd/             # command line interface, binary entrypoint, parses config
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
│  ├─ life/         # lifecycle manager
│  ├─ dbindex/      # badger DB index helper
│
├─ core/            # core workflow; charon business logic (see architecture doc for details)
│  ├─ interfaces.go # component interfaces: Scheduler, Fetcher, Consensus, etc.
│  ├─ manifest.go   # manifest type
│  ├─ types.go      # core workflow types: Duty, PubKey, FetchArg, UnsignedData, etc.
│  ├─ encode.go     # encode/decode the abstract types with type safe API
│  │
│  │                # core workflow component implementations
│  ├─ scheduler/    # scheduler
│  ├─ fetcher/      # fetcher
│  ├─ leadercast/   # consensus implementation (will add qbft later)
│  ├─ dutydb/       # dutydb
│  ├─ validatorapi/ # validatorapi
│  ├─ sigdb/        # sigdb
│  ├─ sigex/        # sigex
│  ├─ sigagg/       # sigagg
│  ├─ aggdb/        # aggdb
│  ├─ broadcast/    # broadcast
│
├─ p2p/             # p2p networking services
│  ├─ p2p.go        # libp2p tcp service, provides inter node communication
│  ├─ discovery.go  # discv5 udp service, peer discovery for libp2p.
│  ├─ ping.go       # ping libp2p protocol
│
├─ tbls/            # bls threshold signature scheme; verify, aggregate partial signatures
│
├─ testutil/        # testing libraries
│  ├─ golden.go     # golden file testing
│  ├─ beaconmock/   # beacon client mock
```
