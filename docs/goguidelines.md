# Charon Go Guidelines

This page contains guidelines, principals and best practices relating to how we write go code.
As an open source project, we need to aim for high code quality, consistency and canonical go.

## Required Knowledge
These resources define opinions and practices that are highly recommended.

- [Effective Go](https://go.dev/doc/effective_go)
- [Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- [Practical Go](https://dave.cheney.net/practical-go/presentations/gophercon-israel.html)
- [Go Proverbs](https://go-proverbs.github.io)
- [The Zen of Go](https://the-zen-of-go.netlify.app/)

## Inspirational projects
We take inspiration and guidance from these top-quality go projects.

- [Vouch](https://github.com/attestantio/vouch)
- [Prysm](https://github.com/prysmaticlabs/prysm)
- [Go-ethereum](https://github.com/ethereum/go-ethereum)
- [Avalanchego](https://github.com/ava-labs/avalanchego)
- [LND](https://github.com/lightningnetwork/lnd)
- [Consul](https://github.com/hashicorp/consul)
- [Dgraph](https://github.com/dgraph-io/dgraph)

## Tradeoffs
Go is a high-level imperative “getting s@&!t done” language but there are always a
thousand ways to approach a problem. Keeping the following priorities in mind should
drive to what the go community refers to as “canonical go”.

- Prefer **unexported over exported** types and functions. [#WriteShyCode](https://dave.cheney.net/practical-go/presentations/qcon-china.html#_package_design)
- Prefer **functions over methods** as methods lends itself to stateful code while functions are stateless. [#FunctionsOverMethods](https://kellysutton.com/2018/07/13/simple-made-easy-methods-vs-functions.html)
- Prefer **structs over objects** as structs tend to be more on the immutable data side while “objects” tend to be mutable and combine data with logic. [#TheValueOfValues](https://www.youtube.com/watch?v=-I-VpPMzG7c)
- Prefer **explicit over implement** as explicit code doesn’t hide anything while implicit code does.
- Prefer **immutability over mutability** as that results in code that is easier to reason about and debug and compose.

## Style
We follow [go fumpt](https://pkg.go.dev/mvdan.cc/gofumpt) , `go vet` and [golangci-lint](https://golangci-lint.run/) for automated formatting and vetting and linting,
but there are still some style related aspects that are not enforced be these tools.
Please try to inform your decisions by the following style for improved consistency.

> Note that style isn’t an exact science #CodeAsCraft

- **New lines**:
  - Please use new lines to structure and group code for improved readability. Think about how prose and poetry uses paragraphs and layout to convey information. #CleanCodeReadsAsProse
  - Prefer new lines between blocks of related code. Functions often have multiple steps, so maybe put a new line and a comment before each step.
  - Think about new lines after indented blocks.
- `**Comments/godocs**:
  - The “Practical Go” articles above has great info on how to comment.
  - Avoid inline comments that are pretty much identical to the actual code. Uncle Bob imagines comments as old-school flashing web1 html instead of soothing background grey. Keep them to a minimum aiming for very high signal to noise.
  - Write long comments as proper sentences: Start with a capital, end with a full stop, grammatically correct.
- **Error handling**:
  - First priority is to just return errors.
  - Avoid logging and returning errors.
  - Avoid swallowing errors.
  - Name error variables `err`.
  - Wrap all errors returned from external libraries for proper stack traces.
  - Prefer returning an error over a panic.
- **Pointers**:
  - Prefer non-pointers over pointers since pointers convey the intent of mutability.
  - Note that passing pointers around is in general not faster than non-pointers (except in some edge cases).
- **Naming**:
  - Data labels should be snake_case. This include json fields, structured logging fields, prometheus labels etc.
  - Go package names should be concise; aim for a single noun (`validator`) or two concatenated nouns (`validatorapi`). Avoid underscores or three word nouns.
