# GoQuorum

GoQuorum is a "fork" of [GoQuorum's](https://consensys.net/docs/goquorum/en/latest/configure-and-manage/configure/consensus-protocols/qbft/)
QBFT consensus protocol as defined in [here](https://github.com/ConsenSys/quorum/tree/master/consensus/istanbul/qbft/core).

## Why though?
- DVT requires consensus on duty data to be signed to ensure safety.
- DVT doesn't however require blockchain type consensus; it neither needs consensus of blocks not do sequential consensus games build a chain.
- DVT instead plays once-off consensus games of arbitrary data (duty data).
- GoQuorum's qbft core protocol provides this... almost.
- GoQuorum however doesn't provide an easily consumable library of the QBFT core protocol.
  - The go module of the repo is identical to go-ethereum, `github.com/ethereum/go-ethereum`, so it cannot easily be imported as a dependency.
  - It also shares the same cgo function definitions as go-ethereum, which causes builds to fail when both are imported.
  - Even though it tries to be decoupled from blocks, there are still a few hidden references to `types.Block`.
- The [fork](fork/fork.go) command provides a tool that generates the library required:
  - Extracts the qbft core protocol from GoQuorum into this project at `goquorum/istanbul/qbft/core`.
  - It trims all non-related packages.
  - It replaces references to `types.Block`.
  - Resulting in a qbft "library" that can be consumed from charon.
