![Obol Logo](https://obol.tech/obolnetwork.png)

<h1 align="center">Charon - The Distributed Validator middleware client</h1>
<!-- [![Tag](https://img.shields.io/github/tag/obolnetwork/charon.svg)](https://github.com/obolnetwork/charon/releases/)
[![License](https://img.shields.io/github/license/obolnetwork/charon.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/obolnetwork/charon?status.svg)](https://godoc.org/github.com/obolnetwork/charon)
![Lint](https://github.com/obolnetwork/charon/workflows/golangci-lint/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/obolnetwork/charon)](https://goreportcard.com/report/github.com/obolnetwork/charon) -->

This repo contains the source code for the distributed validator client *Charon*; a HTTP middleware client for Ethereum Staking that enables you to safely run a single validator across a group of independent servers.

Charon is accompanied by a DKG tool, [Delphi](https://github.com/obolnetwork/delphi), for distributed validator key creation. 

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

- As environment variables beginning with `CHARON_`, with hyphens substituted for underscores. e.g. `CHARON_BEACON_NODE=http://....`
- Declared in a yaml file in `~/.charon.yaml`, e.g. `beacon-node: http://...`
- Passed in as CLI params to the binary, e.g. `--beacon-node http://...`

## Repo Overview

Charon is built in [GoLang](https://golang.org/dl/), with [Cobra](https://cobra.dev/) managing its command line interfaces, and using [Viper](https://github.com/spf13/viper) for it's configuration management.

### Folder Organisation

#### api
Contains files relating to charon's HTTP client and server API

#### cmd
Contains files relating to the command line commands and argument management. Uses [Cobra](https://cobra.dev/).

#### config
Handles the separation of argument parsing from external sources to parameter passing to internal processes. Allows charon processes to declare what parameters they need using the [Golang Functional Options Pattern](https://golang.cafe/blog/golang-functional-options-pattern.html). Uses Cobra's companion package [Viper](https://github.com/spf13/viper).

#### internal
Internal structs and services for the charon client, not intended to be interacted with directly by external consumers.

#### local
Config and data storage mount point for local developement of the charon client with docker-compose. 

#### logging
Helper file for setting log level and overriding zerolog config

#### nginx
Temporary middleman between validator and beacon clients for testing purposes

## Deployment workflow

- Checkout a branch and commit your work
    - Use either a ticket as the branch name or namespace it with your name, e.g. `obol-231` or `oisin/feature`. 
- Open a PR
- Once CI passes it can be merged to `master`
- Commits on master can be tagged for public release with a command like; `git tag -a v0.0.1 -m "Charon v0.0.1: Hello Acheron"`

## To Do List
- [x] Beacon client syncing
- [ ] Validator client connected
- [ ] Weak Subjectivity Working for faster syncs
- [ ] Nginx pass through proxy server
- [x] GoLang Process
- [x] CI/CD to build and test GoLang process
- [ ] Dockerised GoLang Process
- [ ] GoLang process operating as a passthrough HTTP server
- [ ] GoLang pass through proxy server
- [ ] Multiple Validators and Proxy Servers
- [ ] Test suite for DKG
- [ ] Docker Compose file for running an SSV
- [ ] Github CI for GoLang build of source
- [ ] Github CI for Docker build

## Lessons Learned

- I don't want to wait to sync a full testnet, what can I do?
    - You can use what's called wak subjectivity sync, which basically accepts a checkpoint from another node and starts from there. You can get a checkpoint from infura by calling (with the appropriate env vars set):
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