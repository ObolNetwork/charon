# Charon Project Structure

This document outlines the project structure.

```
charon/             # project root
├─ main.go          # charon main package, it just calls cmd/
├─ cmd/             # command line interface, binary entrypoint, parses config
│
├─ app/             # application run entrypoint
│  ├─ app.go        # wires state, manages process lifecycle.
│  │
│  │                # application infrastructure libraries
│  ├─ log/          # logging
│  ├─ errors/       # errors
│  ├─ z/            # structured logging and error fields (wraps zap fields)
│  ├─ tracer/       # tracing
│  ├─ version/      # app version
│  ├─ dbindex/      # badger DB index helper
│
├─ core/            # core workflow; charon business logic (see architecture doc for details)
│  ├─ interfaces.go # component interfaces: Scheduler, Fetcher, Consensus, etc.
│  ├─ types.go      # core types: Manifest, Duty, DutyArg, PubKey, DutyData, etc.
│  ├─ scheduler/    # scheduler implementation
│  ├─ fetcher.go    # fetcher implementation (simple function, no need for separate package)
│  ├─ leadercast/   # consensus implementation (will later add qbft)
│  ├─ dutydb/       # dutydb implementation
│  ├─ validatorapi/ # validatorapi implementation
│  ├─ sigdb/        # sigdb implementation
│  ├─ sigex/        # sigex implementation
│  ├─ sigagg.go     # sigagg implementation (simple function)
│  ├─ aggdb/        # aggdb implementation
│  ├─ broadcast.go  # broadcast implementation (simple function)
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
