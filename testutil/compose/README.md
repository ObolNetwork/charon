# Charon Compose

> Run, test, and debug a developer-focussed insecure local charon cluster using docker-compose

Compose is a tool that generates `docker-compose.yml` files such that different charon clusters can be created and run.

The aim is for developers to be able to debug features and check functionality of clusters on their local machines.

The `compose` command should be executed in sequential steps:
 1. `compose clean`: Cleans the compose directory of existing artifacts.
 2. `compose define`: Defines the target cluster and how keys are to be created.
    1. It outputs `config.json` which is the compose config
    1. It also creates `docker-compose.yml` in order to create `cluster-definition.json` if `keygen==dkg`.
 1. `compose lock`: Creates `docker-compose.yml` to create threshold key shares and the `cluster-lock.json` file.
 1. `compose run`: Creates `docker-compose.yml` to run the cluster.

Note that compose automatically runs `docker-compose up` at the end of each command. This can be disabled via `--up=false`.

The `compose define` step configures the target cluster and key generation process. It supports the following flags:
 - `--keygen`: Key generation process: `create` or `dkg`.
   - create` creates keys locally via `charon create cluster`
   - `dkg` creates keys via `charon create dkg` followed by `charon dkg`.
 - `--split-keys-dir`: Path to a folder containing keys to split. Only applicable to `--keygen=create`.
 - `--build-local`: Build a local charon binary from source. Note this requires the `CHARON_REPO` path env var. Devs are encouraged to put this in the bash profile.
 - `--seed`: Randomness seed, can be used to produce deterministic p2pkeys for dkg.

## Usage
Install the `compose` binary:
```
# From inside the charon repo
go install github.com/obolnetwork/charon/testutil/compose/compose

# Ensure that `.../go/bin` is in your path via `which compose`

# Alternatives:
# go install ./...
# cd testutil/compose/compose && go installl .
# cd testutil/compose/compose && go build -o /tmp/compose/compose
```
Create a charon compose workspace folder:
```
cd /tmp
mkdir charon-compose
cd charon-compose
```
Create the default cluster:
```
compose clean && compose define && compose lock && compose run
```
Monitor the cluster via `grafana` and `jaeger`:
```
open http://localhost:3000/d/B2zGKKs7k # Open Grafana simnet dashboard
open http://localhost:16686            # Open Jaeger dashboard
```
Creating a DKG based cluster that uses locally built binary:
```
compose clean
compose define --keygen=dkg --build-local
compose lock
compose run
```
