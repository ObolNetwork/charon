# Charon Compose

> Run, test, and debug a developer-focussed insecure local charon cluster using docker compose

Compose is a tool that generates `docker-compose.yml` files such that different charon clusters can be created and run.

The aim is for developers to be able to debug features and check functionality of clusters on their local machines.

The `compose` command should be executed in sequential steps:
 1. `compose new`: Creates a new config.json that defines what will be composed.
 2. `compose define`: Creates a docker-compose.yml that executes `charon create dkg` if keygen==dkg.
 3. `compose lock`: Creates a docker-compose.yml that executes `charon create cluster` or `charon dkg`.
 4. `compose run`: Creates a docker-compose.yml that executes `charon run`.

The `compose` command also includes some convenience functions.
- `compose clean`: Cleans the compose directory of existing files.
- `compose auto`: Runs `compose define && compose lock && compose run`.

Note that compose automatically runs `docker compose up` at the end of each command. This can be disabled via `--up=false`.

The `compose new` step configures the target cluster and key generation process. See `compose new --help` for supported flags.

## Usage Examples

Install the `compose` binary:
```
# From inside the charon repo
go install github.com/obolnetwork/charon/testutil/compose/compose

# If `which compose` fails, then fix your environment: `export PATH=$PATH:$(go env GOPATH)/bin`. Or see https://go.dev/doc/gopath_code

# Alternatives:
# go install ./...
# cd testutil/compose/compose && go install .
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
compose clean && compose new && compose define && compose lock && compose run
```

Monitor the cluster via `grafana` and `jaeger`:
```
open http://localhost:3000/d/charon_overview_dashboard/charon-overview  # Open Grafana simnet dashboard
open http://localhost:16686                                             # Open Jaeger dashboard
```

Creating a DKG based cluster that uses locally built binary:
```
compose new --keygen=dkg --build-local
compose auto
```

Creating a cluster splitting existing keys for a public testnet:
```
# Prep the keys to split
# Each keystore-{foo}.json requires a keystore-{foo}.txt file containing the password.
mkdir mykeys
cp path/to/existing/keys/keystore-*.json mykeys/
cp path/to/passwords/keystore-*.txt mykeys/

compose new --split-keys-dir=mykeys --beacon-node=$BEACON_URL
compose auto
```
