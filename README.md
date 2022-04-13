![Obol Logo](https://obol.tech/obolnetwork.png)

<h1 align="center">Charon - The Distributed Validator middleware client</h1>
<!-- [![Tag](https://img.shields.io/github/tag/obolnetwork/charon.svg)](https://github.com/obolnetwork/charon/releases/)
[![License](https://img.shields.io/github/license/obolnetwork/charon.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/obolnetwork/charon?status.svg)](https://godoc.org/github.com/obolnetwork/charon)
![Lint](https://github.com/obolnetwork/charon/workflows/golangci-lint/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/obolnetwork/charon)](https://goreportcard.com/report/github.com/obolnetwork/charon) -->

This repo contains the source code for the distributed validator client *Charon*; a HTTP middleware client for Ethereum Staking that enables you to safely run a single validator across a group of independent nodes.

Charon is accompanied by a webapp called the [Distributed Validator Launchpad](https://github.com/obolnetwork/dv-launchpad) for distributed validator key creation.

Charon is used by Enterprises and DAOs to distribute the responsibility of running Ethereum Validators across a number of different instances and client implementations.

![Example Obol Cluster](https://obol.tech/ObolCluster.png)
###### A validator deployment that uses the Charon client to hedge client and hardware failure risks

## Quickstart

The easiest way to get started is with the [charon-docker-compose](https://github.com/ObolNetwork/charon-docker-compose) repo
which contains a docker compose setup for running a charon cluster on your local machine.

If however, you want to build from source with this repo directly, you can get started with:
```bash
# Install go 1.18 or later (on mac with homebrew installed)
brew install go

# Build the charon binary
go build -o charon

# Use charon's create-cluster command to generate a local simnet cluster.
./charon --help
./charon create-cluster --cluster-dir=/tmp/charon-simnet --config=true --config-simnet
/tmp/charon-simnet/run_cluster.sh
```

## Documentation

The [Obol Docs](https://docs.obol.tech/) website is the best place to get started.
The important sections are the [intro](https://docs.obol.tech/docs/intro),
[key concepts](https://docs.obol.tech/docs/key-concepts) and [charon](https://docs.obol.tech/docs/dv/introducing-charon).

For detailed documentation on this repo, see the [docs](docs) folder:
- [Configuration](configuration.md): Configuring a charon node
- [Architecture](architecture.md): Overview of charon cluster and node architecture
- [Project Structure](structure.md): Project folder structure
- [Branching and Release Model](branching.md): Git branching and release model
- [Go Guidelines](goguidelines.md): Guidelines and principals relating to go development
- [Contributing](contributing.md): How to contribute to charon; githooks, PR templates, etc.

For source code documentation, there is always the [charon godocs](https://pkg.go.dev/github.com/obolnetwork/charon).

## Supported Consensus Layer Clients

Charon integrates into the Ethereum consensus stack as a middleware between the validator client
and the beacon node via the official [Eth Beacon Node REST API](https://ethereum.github.io/beacon-APIs/#/).
Charon supports any upstream beacon node that serves the Beacon API.
Charon supports any downstream standalone validator client that consumes the Beacon API.

| Client                                            | Beacon Node | Validator Client | Notes                                   |
|---------------------------------------------------|-------------|------------------|-----------------------------------------|
| [Teku](https://github.com/ConsenSys/teku)         | ✅           | ✅                | Fully supported                         |
| [Lighthouse](https://github.com/sigp/lighthouse)  | ✅           | ✅                | Fully supported                         |
| [Lodestar](https://github.com/ChainSafe/lodestar) | ✅           | ✅                | Fully supported                         |
| [Vouch](https://github.com/attestantio/vouch)     | *️⃣         | ✅                | Only validator client provided          |
| [Prysm](https://github.com/prysmaticlabs/prysm)   | ✅           | 🛑               | Validator client requires gRPC API      |
| [Nimbus](https://github.com/status-im/nimbus-eth2) | ✅           | *️⃣              | No standalone validator client provided |

## Project Status

It is still early days for the Obol Network and things are under active development.
We are moving fast so check back in regularly to track the progress.

Charon is a distributed validator, so its main responsibility is performing validation duties.
The status of supported duties are (🚧 means "under construction"):

| Duty | Teku VC | Lighthouse VC |
|------|--------|---------------|
| *Attestation* | ✅      | ✅             |
| *Attestation Aggregation* | 🚧     | 🚧            |
| *Block Proposal* | 🚧     | 🚧            |
| *Blinded Block Proposal (mev-boost)* | 🚧     | 🚧            |
| *Sync Committee Attestation* | 🚧     | 🚧            |
| *Sync Committee Aggregation* | 🚧     | 🚧            |
