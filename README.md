![Obol Logo](https://obol.tech/obolnetwork.png)

<h1 align="center">Charon - The Distributed Validator middleware client</h1>
<!-- [![Tag](https://img.shields.io/github/tag/obolnetwork/charon.svg)](https://github.com/obolnetwork/charon/releases/)
[![License](https://img.shields.io/github/license/obolnetwork/charon.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/obolnetwork/charon?status.svg)](https://godoc.org/github.com/obolnetwork/charon)
![Lint](https://github.com/obolnetwork/charon/workflows/golangci-lint/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/obolnetwork/charon)](https://goreportcard.com/report/github.com/obolnetwork/charon) -->

This repo contains the source code for the distributed validator client *Charon*; a HTTP middleware client for Ethereum Staking that enables you to safely run a single validator across a group of independent nodes.

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
### Install Githooks
We use `pre-commit hooks` to ensure that pull requests adhere to a minimum standard and are consistent. To install:
- Follow installation instructions [here](https://pre-commit.com/#installation)
- Once installed, run `pre-commit install` in the project's root directory. This will setup the hooks.
- NOTE: If you don't want to run hooks on every commit, simply disable it by `pre-commit uninstall`

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
