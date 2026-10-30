# Test vectors

Conformance fixtures for implementations of the Obol Distributed Validator
protocol. Each suite is one JSON file, checked in, and consumed directly — there
is no build step and no code generation.

The point of these files is to be a source of truth that is independent of any
one implementation. Where a value could be obtained from Charon, it was, so that
a passing suite means "agrees with Charon" rather than "agrees with this spec".

## Suites

| File                        | Covers                                                                                              | Source  |
| --------------------------- | --------------------------------------------------------------------------------------------------- | ------- |
| `qbft_hashing.json`         | Deterministic protobuf encodings and SSZ hash roots: duties, consensus values, QBFT signing roots, `Any`-wrapped strings | charon  |
| `cluster_hashing.json`      | Cluster config, definition and lock hashes at v1.10.0, and a fully signed lock                       | charon  |
| `bls_threshold.json`        | BLS12-381 keys, partial signatures, threshold (Lagrange) and plain aggregation                       | charon  |
| `secp256k1_signatures.json` | 65-byte `R \|\| S \|\| V` signatures and public key recovery                                        | charon  |
| `priority_scoring.json`     | Cluster-wide priority results from per-peer preference orders                                        | charon  |
| `timer_deadlines.json`      | Consensus round deadlines by genesis, slot duration, slot, duty type and round                      | spec    |
| `qbft_msg_limits.json`      | Justification, value and wire-size limits on an incoming consensus message, and which limit fires   | spec    |
| `qbft_decided_resends.json` | Which post-decision ROUND-CHANGE events may trigger a `DECIDED` rebroadcast                         | charon  |
| `parsigex_sender_binding.json` | Binding a claimed share index to the authenticated sender, and peer map validation               | charon  |
| `cluster_validation.json`   | Which cluster definitions and locks must be accepted or rejected: field lengths, addresses, deposit data, builder registrations | spec    |

The suites chain where the protocol does. The digest signed in
`secp256k1_signatures.json` is the QBFT signing root derived in
`qbft_hashing.json`, so an implementation that gets the encoding wrong fails at
the signature too. The `real_keys_3_of_4` lock in `cluster_hashing.json` reuses the
sharing `bls_threshold.json` pins, so its signature aggregate can only verify if
the lock hash, the public shares and plain aggregation are all right.

## File format

Every suite is an object with:

- `suite` — must equal the filename without its extension.
- `description` — what the suite covers, and any formula needed to interpret it.
- `provenance` — `source` (`charon` or `spec`), `charon_ref` (the commit the
  suite was validated against), `generated_by`, and a `note` explaining how the
  values were obtained.
- One or more arrays of cases. `timer_deadlines` and `priority_scoring` use a
  single `cases` array; `qbft_hashing` groups its cases by message type
  (`duty`, `unsigned_data_set`, `qbft_signing_root`, `any_string`), and
  `cluster_hashing` by object (`definition`, `lock`).

Every case has a `name` unique within its array, an `input` object, and the
expected outputs as sibling keys. Byte strings are lower-case hex without a `0x`
prefix. Some cases carry a `notes` field explaining the rule they pin down —
those are the cases most likely to catch a bug, so start there when debugging.

## Rejection cases

The last four suites are **negative**: they pin what an implementation must
*refuse*, not what it must compute. Every other suite passes by producing a
value, which leaves the reject rules unpinned — an implementation can pass all of
them while accepting a 128 MiB consensus message or a partial signature deposited
into another operator's share slot. Under-rejecting is a denial-of-service hole;
over-rejecting breaks liveness against Charon. Both need a fixture.

Cases in these suites carry:

- `accepted` — whether the input must be accepted.
- `reason` — `null` when accepted, otherwise a stable slug naming the rule that
  fired: `too_many_justifications`, `too_many_values`, `msg_too_large`,
  `share_idx_mismatch`, `unknown_peer`, `missing_share_idx`, and the cluster
  file rules listed below. The slugs are the contract; the wording of an error
  message is not.

Two conventions are worth knowing:

- **Cases come in pairs around each boundary.** `justifications_at_limit` and
  `justifications_one_over_limit` differ by one. A suite of rejections alone
  cannot distinguish a correct limit from one that rejects everything.
- **The reason is asserted, not just the rejection.** Charon checks the
  justification count before the value count, so a message exceeding both is
  rejected for its justifications — `both_limits_exceeded_reports_justifications`
  pins exactly that. Two implementations that reject the same inputs for
  different reasons have not agreed on the protocol.

`qbft_decided_resends` is shaped differently, because the rule is stateful: each
case is a *sequence* of ROUND-CHANGE events, and `rebroadcast[i]` says whether
event `i` triggers a rebroadcast. Replay the events in order against one instance.
Counts are rebroadcast *events*, not messages, since one rebroadcast reaches every
peer.

`cluster_validation` holds whole cluster files. Each `definition` case is
accepted if it parses under the field rules and its stored hashes verify; each
`lock` case if it parses and passes the full verification sequence of
`dv_spec.cluster.verification.verify_lock`, with `node_pubkeys` standing in for
the keys in the operators' ENRs. Its reason slugs are `invalid_length`,
`invalid_address`, `bad_address_checksum`,
`deposit_amount_out_of_range`, `deposit_amounts_sum_too_low`,
`deposit_pubkey_mismatch`,
`withdrawal_credentials_mismatch`, `deposit_amount_not_in_definition`,
`invalid_deposit_signature`, `registration_pubkey_mismatch`,
`registration_fee_recipient_mismatch` and `invalid_registration_signature`.
Two properties make the suite bite:

- **Every rejected case breaks exactly one rule.** Its hashes are recomputed,
  and its signature aggregate, node signatures, deposit data and builder
  registration re-signed with real keys, so there is nothing else to reject it
  for.
- **Malformed lengths and addresses are signed as a lenient reader sees them.**
  A 20-byte `withdrawal_credentials` is hashed and signed as the 32 bytes
  Charon's left-padding turns it into; a mis-checksummed address as the bytes it
  decodes to. A reader that pads instead of rejecting finds every hash and
  signature valid, so only the field rule itself rejects the file.
  `tests/test_vectors.py` checks this by repairing each such case the lenient
  way and verifying it.

`cluster_hashing` and `cluster_validation` are the exceptions to the hex
convention, and deliberately:
each case's `input` is a verbatim Charon cluster file, so inside `input` the
encoding is Charon's own — `0x` prefixed hex, Gwei amounts as JSON strings, and
`null` for empty lists. Consuming these cases means parsing the real file format
rather than a transcription of it. The expected hashes alongside `input` follow the
bare-hex convention like every other suite.

## Provenance

`source: charon` means the expected values came out of Charon, not out of this
spec:

- `qbft_hashing.json` was produced by `charon/hashproto_generator/main.go`, which
  copies Charon's `hashProto` verbatim and calls Go's
  `proto.MarshalOptions{Deterministic: true}`.
- `bls_threshold.json` and `secp256k1_signatures.json` were produced by
  `charon/crypto_generator/main.go`, calling Charon's `tbls` and `app/k1util`
  packages. The BLS key shares are spec-chosen inputs; everything derived from
  them — public shares, signatures, aggregates — is Charon's output. Charon's
  `RecoverSecret` over shares 1–3 returning the group secret is what confirms
  the sharing is valid and that secret keys are big-endian.
- `cluster_hashing.json` was produced by `charon/cluster_generator/main.go`, which
  calls Charon's exported `Definition.SetDefinitionHashes` and `Lock.SetLockHash`
  and writes the inputs with Charon's own JSON marshaller. Its
  `charon_testdata_golden` cases are Charon's regression fixtures
  `cluster/testdata/cluster_definition_v1_10_0.json` and
  `cluster_lock_v1_10_0.json`, unmodified, which Charon's own `TestEncode` asserts.
  The generator refuses to emit the `real_keys_3_of_4` lock unless Charon accepts
  its signature aggregate and each node signature against the key in the
  corresponding operator's ENR.

- `priority_scoring.json` expectations are transcribed from Charon's
  `core/priority/calculate_internal_test.go` `TestCalculateResults` table.
  `scripts/generate_test_vectors.py` fails if this spec does not reproduce them.

- `qbft_decided_resends.json` event sequences and counts are transcribed from
  Charon's `core/qbft/qbft_internal_test.go` `TestDecidedRebroadcastLimits`
  subtests, and `parsigex_sender_binding.json`'s six sender cases from
  `dkg/exchanger_internal_test.go` `TestVerifyPeerShareIdx`, one for one. Of the
  peer-map cases, only the missing-peer rejection is Charon's
  (`TestNewExchangerRejectsIncompletePeerMap` has exactly that one case); the
  accepted map and the non-positive-index rejection are spec-added boundaries
  around the same `newExchanger` rule. The generator replays every case through
  the spec and fails on any disagreement.

`qbft_msg_limits.json` is `source: spec`: the cases are boundary pairs the spec
derives from Charon's formulas (`maxJust = 2*nodes`, `maxValues =
2*(justifications+1)`) and constants (`maxConsensusMsgSize`, and
`p2p/sender.go`'s 128 MiB default that consensus overrides), not values Charon
emitted. Charon's own `TestQBFTConsensusHandleAmplificationLimits` pins the same
at/over boundaries for a one-node cluster; the suite re-derives them for 3-, 4-
and 7-node clusters and adds the both-limits-exceeded precedence case and the
wire-size pairs, which Charon does not table.

To reproduce a Go-generated suite: copy the generator's directory into a Charon
checkout at the `charon_ref` commit as `zz_spec_vectors/`, run
`go run ./zz_spec_vectors` from the checkout root, and compare. Each generator
lives in its own directory because they are all `package main`; side by side in
one directory they would not compile. The cluster generator reads Charon's
testdata by relative path, so it must be run from the checkout root.

`cluster_validation.json` is `source: spec` and is **stricter than Charon at the
anchor**: Charon accepts most of its rejected cases today. The keys are reused
rather than invented — the BLS sharing from `bls_threshold.json`, and the
operator ENRs and node keys from `cluster_hashing.json`'s `real_keys_3_of_4` lock
— so its valid locks are verifiable by Charon from the ENRs alone. Charon at the
anchor accepts every accepted case.

Note that `cluster_hashing.json` records a `charon_ref` one commit ahead of the
`2eb6798e` every other original suite records. That commit touches only
`p2p/sender_test.go`, so `cluster/` is identical at both; the field records where
the suite was actually generated rather than the repository's overall anchor. The
three Charon-transcribed rejection suites, and `cluster_validation.json`, record
the current anchor (`6054bcb2`), which is where their tables were transcribed
from or their rules compared against.

`source: spec` means this spec computed the values from its reading of Charon's
source. `timer_deadlines.json` is in this category: the deadlines are plain
arithmetic, but no Charon test exposes them as a table.

## Regenerating

```bash
uv run python scripts/generate_test_vectors.py
```

This rewrites the `source: spec` suites (`cluster_validation.json` is built by
`scripts/cluster_validation_vectors.py`, which fails if the spec's verdict or
reason for any case differs from the one it was built for) and re-checks
`priority_scoring.json`,
`qbft_decided_resends.json` and `parsigex_sender_binding.json` against Charon's
tables. It deliberately does not touch `qbft_hashing.json` or
`cluster_hashing.json`, which require a Go toolchain and a Charon checkout — see
above.

`tests/test_vectors.py` runs every suite against the spec, so a suite that
drifts from the implementation fails the normal test run.

[`consumers/`](../consumers/README.md) holds the same suites wired into a real
implementation. That is where a vector stops being a document: charon runs all
of them.

## Units and precision

`timer_deadlines.json` is expressed in integer nanoseconds, and those integers
are normative. Charon computes deadlines with `time.Duration`, so the slot
fraction for attester and aggregator duties is an integer division: a 5s slot
gives an attester delay of 1666666666ns. A float cannot hold a unix timestamp to
nanosecond resolution, so an implementation that compares deadlines exactly must
use integers.
