# QBFT

Package `qbft` is an implementation of the ["The Istanbul BFT Consensus Algorithm"](https://arxiv.org/pdf/2002.03613.pdf) by Henrique Moniz
as referenced by the [QBFT spec](https://github.com/ConsenSys/qbft-formal-spec-and-verification).

## Features

- Simple API, just a single function: `qbft.Run`.
- Consensus on arbitrary data.
- Transport abstracted and not provided.
- Decoupled from process authentication and message signing (not provided).
- No dependencies.
- Explicit justifications.

## TODO
 - Add specific Byzantium tests.
 - Add long-running tests. Workaround for now: while go test . -count=10 -timeout=5s; do; done
