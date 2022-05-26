<div align="center"><img src="./docs/images/charonlogo.svg" /></div>
<h1 align="center">Charon<br/>The Distributed Validator middleware client</h1>

<p align="center"><a href="https://github.com/obolnetwork/charon/releases/"><img src="https://img.shields.io/github/tag/obolnetwork/charon.svg"></a>
<a href="https://github.com/ObolNetwork/charon/blob/main/LICENSE"><img src="https://img.shields.io/github/license/obolnetwork/charon.svg"></a>
<a href="https://godoc.org/github.com/obolnetwork/charon"><img src="https://godoc.org/github.com/obolnetwork/charon?status.svg"></a>
<a href="https://goreportcard.com/report/github.com/obolnetwork/charon"><img src="https://goreportcard.com/badge/github.com/obolnetwork/charon"></a>
<a href="https://github.com/ObolNetwork/charon/actions/workflows/golangci-lint.yml"><img src="https://github.com/obolnetwork/charon/workflows/golangci-lint/badge.svg"></a></p>

This repo contains the source code for the distributed validator client _Charon_ (pronounced 'kharon'); a HTTP middleware client for Ethereum Staking that enables you to safely run a single validator across a group of independent nodes.

Charon is accompanied by a webapp called the [Distributed Validator Launchpad](https://github.com/obolnetwork/dv-launchpad) for distributed validator key creation.

Charon is used by Enterprises and DAOs to distribute the responsibility of running Ethereum Validators across a number of different instances and client implementations.

![Example Obol Cluster](https://obol.tech/ObolCluster.png)

###### A validator deployment that uses the Charon client to hedge client and hardware failure risks

## Quickstart

The easiest way to get started is with the [charon-docker-compose](https://github.com/ObolNetwork/charon-docker-compose) repo
which contains a docker compose setup for running a charon cluster on your local machine.

If however, you want to build from source with this repo directly, you can get started with:

```bash
# Install go 1.18 or later (https://go.dev/doc/install)
# If on mac, you can also install using homebrew
brew install go

# Build the charon binary
go build -o charon

# Use charon's create cluster command to generate a local charon cluster
./charon create cluster

# For help, run
./charon --help
```

## Documentation

The [Obol Docs](https://docs.obol.tech/) website is the best place to get started.
The important sections are [intro](https://docs.obol.tech/docs/intro),
[key concepts](https://docs.obol.tech/docs/key-concepts) and [charon](https://docs.obol.tech/docs/dv/introducing-charon).

For detailed documentation on this repo, see the [docs](docs) folder:

- [Configuration](docs/configuration.md): Configuring a charon node
- [Architecture](docs/architecture.md): Overview of charon cluster and node architecture
- [Project Structure](docs/structure.md): Project folder structure
- [Branching and Release Model](docs/branching.md): Git branching and release model
- [Go Guidelines](docs/goguidelines.md): Guidelines and principals relating to go development
- [Contributing](docs/contributing.md): How to contribute to charon; githooks, PR templates, etc.

There is always the [charon godocs](https://pkg.go.dev/github.com/obolnetwork/charon) for the source code documentation.

## Supported Consensus Layer Clients

Charon integrates into the Ethereum consensus stack as a middleware between the validator client
and the beacon node via the official [Eth Beacon Node REST API](https://ethereum.github.io/beacon-APIs/#/).
Charon supports any upstream beacon node that serves the Beacon API.
Charon supports any downstream standalone validator client that consumes the Beacon API.

| Client                                             | Beacon Node | Validator Client | Notes                                   |
| -------------------------------------------------- | ----------- | ---------------- | --------------------------------------- |
| [Teku](https://github.com/ConsenSys/teku)          | ✅          | ✅               | Fully supported                         |
| [Lighthouse](https://github.com/sigp/lighthouse)   | ✅          | ✅               | Fully supported                         |
| [Lodestar](https://github.com/ChainSafe/lodestar)  | ✅          | ✅               | Fully supported                         |
| [Vouch](https://github.com/attestantio/vouch)      | \*️⃣         | ✅               | Only validator client provided          |
| [Prysm](https://github.com/prysmaticlabs/prysm)    | ✅          | 🛑               | Validator client requires gRPC API      |
| [Nimbus](https://github.com/status-im/nimbus-eth2) | ✅          | \*️⃣              | No standalone validator client provided |

## Project Status

It is still early days for the Obol Network and things are under active development.
We are moving fast so check back in regularly to track the progress.

Charon is a distributed validator, so its main responsibility is performing validation duties.
The status of supported duties are (🚧 means "under construction"):

| Duty                                 | Teku VC | Lighthouse VC |
| ------------------------------------ | ------- | ------------- |
| _Attestation_                        | ✅      | ✅            |
| _Attestation Aggregation_            | 🚧      | 🚧            |
| _Block Proposal_                     | 🚧      | 🚧            |
| _Blinded Block Proposal (mev-boost)_ | 🚧      | 🚧            |
| _Sync Committee Attestation_         | 🚧      | 🚧            |
| _Sync Committee Aggregation_         | 🚧      | 🚧            |
