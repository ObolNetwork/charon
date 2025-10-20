# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Charon is a distributed validator middleware client for Ethereum staking that enables running a single validator across a group of independent nodes using threshold BLS signatures. The project is written in Go and implements a sophisticated workflow architecture for coordinating validator duties across multiple nodes in a cluster.

## Build and Development Commands

### Building
```bash
# Build the charon binary
make charon

# Or manually
go build -trimpath -ldflags="-buildid= -s -w -X github.com/obolnetwork/charon/app/version.version=$(bash charon_version.sh)"
```

### Testing
```bash
# Run all tests
go test ./...

# Run tests with race detection (used in pre-commit hooks)
go test -failfast -race -timeout=2m ./...

# Run tests for specific package
go test ./core/scheduler

# Run a single test function
go test -run TestFunctionName ./path/to/package

# Run tests with verbose output
go test -v ./...
```

### Linting and Code Quality
```bash
# Run linter (as per .golangci.yml config)
golangci-lint run

# Format code
go fmt ./...
gofumpt -w .

# Fix imports
fiximports

# Run all pre-commit hooks manually
pre-commit run --all-files
```

### Development Tools
Development tools are defined in go.mod and can be installed via:
```bash
go install tool  # e.g., go install github.com/bufbuild/buf/cmd/buf
```

## Architecture

### Core Workflow Components
The heart of Charon is the **core workflow**, which processes validator duties through a series of components. Each duty (attestation, block proposal, etc.) flows through these stages:

1. **Scheduler** → Triggers duties at optimal times based on beacon chain state
2. **Fetcher** → Fetches unsigned duty data from beacon node
3. **Consensus** → Uses QBFT (Istanbul BFT) to agree on duty data across all nodes
4. **DutyDB** → Persists agreed-upon unsigned data and acts as slashing protection
5. **ValidatorAPI** → Serves data to validator clients and receives partial signatures
6. **ParSigDB** → Stores partial threshold BLS signatures from local and remote VCs
7. **ParSigEx** → Exchanges partial signatures with peers via libp2p
8. **SigAgg** → Aggregates partial signatures when threshold is reached
9. **AggSigDB** → Persists aggregated signatures
10. **Bcast** → Broadcasts final aggregated signatures to beacon node

### Key Abstractions
- **Duty**: Unit of work (slot + duty type). Cluster-level, not per-validator.
- **PubKey**: DV root public key, the identifier for a validator in the workflow
- **UnsignedData**: Abstract type for attestation data, blocks, etc.
- **SignedData**: Fully signed duty data
- **ParSignedData**: Partially signed data from a single threshold BLS share

### Important Design Patterns
- **Immutable values flowing between components**: Components consume and produce immutable values (like actors)
- **Callback subscriptions**: Components are decoupled via subscriptions rather than direct calls
- **Type-safe encoding**: Abstract types (UnsignedData, SignedData) are encoded/decoded via [core/encode.go](core/encode.go)

### Consensus
Charon uses **QBFT** (implementation of Istanbul BFT) for consensus. See [core/qbft/README.md](core/qbft/README.md). Each duty requires consensus to ensure all nodes sign identical data (required for BLS threshold signatures and slashing protection).

### Package Structure
```
app/          # Application entrypoint, wiring, infrastructure libraries (log, errors, tracer, lifecycle)
cluster/      # Cluster config, lock files, DKG artifacts
cmd/          # CLI commands (run, dkg, create, test, etc.)
core/         # Core workflow business logic and component implementations
dkg/          # Distributed Key Generation logic
eth2util/     # ETH2 utilities (signing, deposits, keystores)
p2p/          # libp2p networking and discv5 peer discovery
tbls/         # Threshold BLS signature scheme
testutil/     # Test utilities, mocks, golden files
```

### Dependency Replacements
- Uses forked `github.com/ObolNetwork/kryptology` (security fixes)
- Uses forked `github.com/ObolNetwork/go-eth2-client` (kept up to date with upstream)

## Code Style and Guidelines

### Go Version
Requires Go 1.25 (enforced by pre-commit hooks)

### Core Principles (from [docs/goguidelines.md](docs/goguidelines.md))
1. **Functions over methods**: Prefer stateless functions over stateful objects
2. **Values over types**: Prefer immutable structs over mutable objects
3. **Explicit over implicit**: Don't hide behavior
4. **Unexported over exported**: Write shy code, minimize public surface area

### Error Handling
- Just return errors, avoid logging and returning
- Wrap external library errors for stack traces
- Use concise error messages: `errors.Wrap(err, "do something")` not `"failed to do something"`
- Use `app/errors` package for structured errors with fields

### Logging Guidelines
- **Maximize signal-to-noise ratio** - keep logs scannable
- Levels: `error` (critical, human intervention), `warn` (important failures), `info` (high-level outcomes), `debug` (important steps)
- No `trace` level - only use `debug` for tracing, mark with TODOs to remove
- Keep messages concise and glanceable
- Use snake_case for log fields

### Testing
- Test files use `_test.go` suffix
- Internal tests use `_internal_test.go` (package name with `_test` suffix not used)
- Pre-commit hook runs: `go test -failfast -race -timeout=2m` on touched packages
- Use `testutil/` packages for mocks, golden files, etc.

### Naming Conventions
- Data labels (json, logs, metrics): `snake_case`
- Package names: concise single or double nouns (e.g., `scheduler`, `validatorapi`)
- Variable names: short and clear (`err` for errors, not `error`)

## Common Tasks

### Working with the Core Workflow
When modifying core workflow components:
1. Check [docs/architecture.md](docs/architecture.md) for component interfaces and data flow
2. Ensure immutability - call `.Clone()` before sharing/caching values
3. Update component subscriptions in the stitching logic if interfaces change
4. Component implementations are in `core/<component>/` directories

### Adding New Duty Types
New duty types must be added to:
- `core/types.go`: Add duty type constant
- `core/encode.go`: Add encoding/decoding logic
- Scheduler, Fetcher, and other relevant components

### Working with Cluster Lock Files
- `cluster-definition.json`: Intended cluster config (operators, validators)
- `cluster-lock.json`: Extends definition with DV public keys and shares (output of DKG)
- See [cluster/](cluster/) package

## PR and Commit Guidelines

### PR Title Format
Follow Go team's format: `package[/path]: concise overview of change`
- Examples: `core/scheduler: add sync committee support`, `app/log: improve structured logging`

### PR Body Format
```
Description of the change in present tense.

category: <refactor|bug|feature|docs|release|tidy|fixbuild>
ticket: <#123 or none>
feature_flag: <optional, from app/featureset>
```

### Merge Policy
- PRs are **always squash merged** to main
- PR title and body become the commit message
- Only obol-bulldozer bot can merge (add `merge when ready` label after approval)
- Multiple PRs per issue are encouraged (micro-commits on stable trunk)

## Version Compatibility
- **Compatible**: Same MAJOR version, different MINOR/PATCH
- **Incompatible**: Different MAJOR version
- **DKG**: Requires matching MAJOR and MINOR versions (PATCH can differ)

## Important Notes
- No `trace` logs - use `debug` with TODOs for temporary tracing
- Review and clean up logs periodically
- Prefer functions returning functions over creating new types with methods
- Always verify code doesn't contain security issues before committing
- Use pre-commit hooks (`pre-commit install`) for fast local feedback
