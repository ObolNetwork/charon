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
thousand ways to approach a problem. The Charon codebase doesn't follow the common OOP-like style which emphasises *types and interfaces*.
Instead, it follows a more procedural style for a focus on *functions and values*, [#AlgorthimsAndDataStructuresOverTypes](https://en.wikipedia.org/wiki/Object-oriented_programming#cite_note-48). This style can be summarized by the following tradeoffs:

- Prefer **unexported over exported** types and functions. [#WriteShyCode](https://dave.cheney.net/practical-go/presentations/qcon-china.html#_package_design)
- Prefer **functions over methods** as methods lends itself to stateful code while functions are stateless. [#FunctionsOverMethods](https://kellysutton.com/2018/07/13/simple-made-easy-methods-vs-functions.html)
- Prefer **structs over objects** as structs tend to be more on the immutable data side while “objects” tend to be mutable and combine data with logic. [#TheValueOfValues](https://www.youtube.com/watch?v=-I-VpPMzG7c)
- Prefer **explicit over implement** as explicit code doesn’t hide anything while implicit code does.
- Prefer **immutability over mutability** as that results in code that is easier to reason about and debug and compose.

> Note that we do use types and interfaces and methods and mutable state when required, we just prefer immutable values and functions where applicable.

The following are examples of *functions and values over types*:
### Prefer functions returning functions over new types with methods #1
```go
// startReadyChecker returns a function that returns true if the app is ready.
isReady := startReadyChecker(foo, bar)
// Use the isReady function
for isReady() { ... }
```
vs
```go
// newReadyChecker returns a checker instance that has a IsReady method that returns true if the app is ready.
checker := newReadyChecker(foo, bar)
// Use the checker instance
for checker.IsReady() { ... }
```
Reasoning: The startReadyChecker contains all state and logic in one function and the resulting isReady function cannot be misused. The checker instance introduces a new type with fields that are accessible and can therefore be misused, it is also at risk of being extended with more logic and coupling.

### Prefer functions returning functions over new types with methods #2
```go
// newFooHandler returns a http.HandlerFunc for handling foo requests.
mux.Handle("/foo", newFooHandler(dependencies))
```
vs
```go
// newServer returns a server instance with http.HandlerFunc methods handling all requests (including foo requests).
server := newServer(dependencies)
mux.Handle("/foo", server.handleFoo)
```
Reasoning: The newFooHandler is completely decoupled from other handlers, except via explicit dependencies. The server struct will grow and grow and will attract shared state and coupling.

### Prefer function local variables and anonumous mutation functions over fields and methods
```go
func foo() {
   var x,y,z int
   updateState := func(x2,y2,z2 int) {
     // Update x,y,z in one place
   }

   // Call updateState when required
}
```
vs
```go
type fooer struct {
  x,y,z int
}
func (f fooer) foo() {
  // Call f.updateState when required
}
func (f fooer) updateState(x2,y2,z2 int) {
  // Update x,y,z in one place
}
```
Reasoning: Function local variables cannot be leaked and misuse is much harder than struct fields which are accessible from anywhere.

## Style
We follow [go fumpt](https://pkg.go.dev/mvdan.cc/gofumpt) , `go vet` and [golangci-lint](https://golangci-lint.run/) for automated formatting and vetting and linting,
but there are still some style related aspects that are not enforced be these tools.
Please try to inform your decisions by the following style for improved consistency.

> Note that style isn’t an exact science #CodeAsCraft

### New lines:
  - Please use new lines to structure and group code for improved readability. Think about how prose and poetry uses paragraphs and layout to convey information. #CleanCodeReadsAsProse
  - Prefer new lines between blocks of related code. Functions often have multiple steps, so maybe put a new line and a comment before each step.
  - Think about new lines after indented blocks.

### Comments/godocs:
  - The “Practical Go” articles above has great info on how to comment.
  - Avoid inline comments that are pretty much identical to the actual code. Uncle Bob imagines comments as old-school flashing web1 html instead of soothing background grey. Keep them to a minimum aiming for very high signal to noise.
  - Write long comments as proper sentences: Start with a capital, end with a full stop, grammatically correct.

### Error handling:
  - First priority is to just return errors.
  - Avoid logging and returning errors.
  - Avoid swallowing errors.
  - Name error variables `err`.
  - Wrap all errors returned from external libraries for proper stack traces.
  - Prefer returning an error over a panic.
  - Keep error messages consistent and concise.
    - When wrapping just state the action that failed: `errors.Wrap(err, "do something")` over `errors.Wrap(err, "failed to do something")`
    - Prefer simple consist language: `errors.New("invalid foo")` over `errors.New("foo is invalid")`
    - See the go stdlib packages for examples: `net`, `os`
  - Only add error fields that the caller is unaware of:
    - If a function has an argument `peer`, don’t add a `peer` field to the error, since the caller can decide to add that field when wrapping or logging.
    - If the function has an argument `peers`, then one can add a `peer` field to the error since the caller cannot know which peer failed.

### Logging:
  - The name of the game when it comes to logging is maximize **Signal to Noise** ratio.
    - Many projects have the problem of too much logging.
    - If logs are too much and one can only search for specific logs, then identifying unexpected behaviour becomes very hard.
    - Our aim is that humans should be able follow ALL logs (up to debug level) of a node with 1 validator.
  - Keep logging as simple and concise as possible (ask ChatGPT to help you with this).
  - Focus on glanceability and readability, users should be able to scan logs and quickly identify unexpected behaviour.
  - Stick to similar patterns for similar scenarios and packages.
  - Avoid adding too many fields to logs, since that makes it harder to scan logs.
  - Only add logging fields that are actually useful and actionable. E.g., a `hash` or `signature` is rarely actionable.
  - The following log levels are used:
    - `error`: Critical failures that require human intervention. [almost never used]
    - `warn`: Important failures that do not require human intervention. [rarely used]
    - `info`: Info logs describe the outcomes of high level process or critical information very valuable to the user. [seldom used]
    - `debug`: Debug logs describe important steps within a process. Each process may only log a few of these. [sometimes used]
  - Note we do not support `trace` logs. Only use `debug` logs to trace the execution of functions by marking it with `TODOs` to remove before the next release.
  - Review logs every few releases and remove or decrease the level of logs that are no longer useful. Also remove fields that are not actually used.

### Pointers:
  - Prefer non-pointers over pointers since pointers convey the intent of mutability.
  - Note that passing pointers around is in general not faster than non-pointers (except in some edge cases).

### Naming:
  - Data labels should be snake_case. This include json fields, structured logging fields, prometheus labels etc.
  - Go package names should be concise; aim for a single noun (`validator`) or two concatenated nouns (`validatorapi`). Avoid underscores or three word nouns.

### Declarations:
  - Follow [Dave Cheney's Practical](https://dave.cheney.net/practical-go/presentations/gophercon-israel.html#_use_a_consistent_declaration_style) Go for declarations.
  - TL;DR:
    - Use `var foo <type>` when declaring zero types.
    - Prefer `var foo []slice` over micro-optimization of pre-defining slice lengths, unless in specific hot path.
