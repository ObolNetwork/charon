![Obol Logo](https://obol.tech/obolnetwork.png)

<h1 align="center">Charon - The Distributed Validator middleware client</h1>
<!-- [![Tag](https://img.shields.io/github/tag/obolnetwork/charon.svg)](https://github.com/obolnetwork/charon/releases/)
[![License](https://img.shields.io/github/license/obolnetwork/charon.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/obolnetwork/charon?status.svg)](https://godoc.org/github.com/obolnetwork/charon)
![Lint](https://github.com/obolnetwork/charon/workflows/golangci-lint/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/obolnetwork/charon)](https://goreportcard.com/report/github.com/obolnetwork/charon) -->

This repo contains the source code for the distributed validator client *Charon*; a HTTP middleware client for Ethereum Staking that enables you to safely run a single validator across a group of independent servers.

Charon is accompanied by webapp called the [Distributed Validator Launchpad](https://github.com/obolnetwork/dv-launchpad), for distributed validator key creation. 

Charon is used by Enterprises and DAOs to distribute the responsibility of running Ethereum Validators across a number of different running instances and client implementations.  

![Example Obol Cluster](https://obol.tech/ObolCluster.png)
###### A validator deployment that uses the Charon client to hedge client and hardware failure risks

## Quickstart

This repo contains the GoLang source code for the middleware, a docker-compose file for deploying the client in a local dev environment, and deployment files for deploying this client to a test cluster. To get started:

```bash
# Setup env vars, copy .env.template and then manually enter the correct secrets for the likes of Eth1 nodes etc.
cp .env.template .env

# Local development
make up
```

### Compile and Test Locally

First you need to have [Go 1.17 installed](https://golang.org/doc/go1.17), then you need to run Go build:
```sh
# On mac with homebrew installed
brew install go

# Used for building from source
go build

# Run the charon client
./charon --help
```

### Configuration

In descending order, the Charon client checks the following places for client configuration info:

- From environment vars beginning with `CHARON_`, with hyphens substituted for underscores. e.g. `CHARON_BEACON_NODE=http://....`
- From the config file specified with the `-config-file` flag as YAML, e.g. `beacon-node: http://...`
- From CLI params, e.g. `--beacon-node http://...`

### Project structure

Charon is written in [Go](https://golang.org/dl/). Notable dependencies:
- [Go Ethereum](https://pkg.go.dev/github.com/ethereum/go-ethereum): Ethereum libraries
- [Prysm](https://pkg.go.dev/github.com/prysmaticlabs/prysm): Eth2 libraries
- [spf13/cobra](https://pkg.go.dev/github.com/spf13/cobra): CLI interface
- [spf13/viper](https://pkg.go.dev/github.com/spf13/viper): Config management
- [gRPC](https://grpc.io) and [gRPC-Gateway](https://grpc-ecosystem.github.io/grpc-gateway/): REST API interfaces

### Release Process

Charon is set up to run a release with Github Actions triggered by a Tag. To tag a commit for release run:
```
git tag -a v0.1.0 -m "Charon v0.1.0: Getting Started"
```

## Lessons Learned

- I don't want to wait to sync a full testnet, what can I do?
    - You can use what's called weak subjectivity sync, which basically accepts a checkpoint from another node and starts from there. You can get a checkpoint from infura by calling (with the appropriate env vars set):
    ```log
    curl https://${INFURA_PROJECT_ID}:${INFURA_PROJECT_SECRET}@eth2-beacon-prater.infura.io/eth/v1/beacon/states/finalized/finality_checkpoints
    ```
    - Then take the state root from this response + the epoch and set them in the `TEKU_WS_CHECKPOINT` env var and restart your docker-compose. Teku should start a sync from the checkpoint epoch you've given it instead of from the start. 

## Bugs encountered / gotchas

- Teku fails to start on a new chain if there is data in the temporary db stored in `./local/.data/teku/`. Error is like:
    ```log
    beacon  | Supplied deposit contract (0x77f7bed277449f51505a4c54550b074030d989bc) does not match the stored database (). Check that the existing database matches the current network settings.
    ```
    - Fixed by `rm -rf ./local/.data/teku` 

- `charon test beacon` errors with an error something like: `panic: parse 192.168.2.2:5051: first path segment in URL cannot contain colon`.
    - The issue is `beacon-node` URIs need to specify a `scheme`, prepend IP addresses with `http://`. 

- If you put your laptop into standby while running the local containers (e.g. overnight), when your computer un-suspends, prometheus will fail to scrape endpoints with errors like `unable to append`, `out of bounds`, `time too far into the past or too far into the future`. 
    - The issue is the containers system clocks get way out of sync. Fix by turning them off and on again, classic.