# Post-Mortem: QBFT Compare Timer Race Condition

**Date**: 2026-03-09
**Severity**: Medium — 2.5% attester duty failure rate across affected nodes in mainnet fleet
**Duration**: Ongoing from 2026-03-09 ~10:00 UTC, fix shipped in v1.9.2-rc1
**Author**: Oisin Kyne

## Summary

A race condition in the QBFT consensus `compare()` function caused spurious round timeouts when the eager double-linear timer's absolute deadline expired before the Compare callback was scheduled by the Go runtime. The bug was latent in all versions with the Compare mechanism (v1.8.x, v1.9.0, v1.9.1) but was triggered fleet-wide by a DNS outage that shifted p2p message delivery timing past a critical threshold.

## Impact

- **Global mainnet attester timeout rate**: ~100/h (baseline) → ~2,700/h (25x increase)
- **Per-cluster failure rate**: ~2.5% of attester duties affected
- **Consensus decisions**: still occurred in most cases (round 2+), but with elevated latency (p99: 1.7s → 4.8s)
- **No slashing risk**: the bug caused missed consensus rounds, not conflicting signatures
- **Economic impact**: marginal — affected attestations were delayed, not permanently lost

## Timeline

| Time (UTC) | Event |
|---|---|
| 2026-03-09 ~09:40 | DNS outage begins — Obol domain names unreachable for ~20 minutes |
| 2026-03-09 ~09:40 | Prometheus remote write (Victoria Metrics) stops receiving data — visible as metrics gap |
| 2026-03-09 ~10:00 | DNS resolves — p2p connections re-establish with slightly different routing/latency |
| 2026-03-09 ~10:30 | Attester consensus timeouts begin climbing globally |
| 2026-03-09 ~11:00 | Global rate stabilises at ~2,700/h (from ~100/h baseline) |
| 2026-03-11 | Claude Code Investigation begins — initially attributed to slow beacon nodes |
| 2026-03-10 | BN latency confirmed at 5ms throughout — not a beacon node issue |
| 2026-03-10 | `compareAttestations` confirmed `false` on all affected clusters — Compare callback returns nil instantly |
| 2026-03-10 | Race condition identified: Go `select` non-deterministically picks between simultaneously-ready `compareErr` and `timerChan` channels |
| 2026-03-11 | Fix shipped in v1.9.2-rc1 (Compare mechanism removed entirely) |
| 2026-03-11 | plain-garden upgraded on test cluster — compare timeouts drop to 0 immediately |

## Root Cause

### The Bug

In `core/qbft/qbft.go`, the `compare()` function (lines 438-466 in v1.9.1) waits on three channels:

```go
select {
case err := <-compareErr:    // Compare callback result
case inputValueSource = <-compareValue:  // Local value for comparison
case <-timerChan:            // Round timer
    log.Warn(ctx, "", errors.New("timeout waiting for local data..."))
    return inputValueSource, errTimeout
}
```

The `d.Compare` callback runs in a goroutine and sends `nil` on `compareErr` almost instantly when `compareAttestations` is `false` (the case for all production clusters — the feature was gated behind the `chain_split_halt` alpha flag that was rarely enabled).

The `timerChan` comes from the `EagerDoubleLinear` round timer, which calculates **absolute deadlines** based on slot start time:

- First call: `deadline = slotStart + dutyDelay + roundTimeout` (e.g., `slotStart + 4s + 1s = slotStart + 5s`)
- Second call (on justified pre-prepare): `deadline = firstDeadline + roundTimeout` (e.g., `slotStart + 5s + 1s = slotStart + 6s`)

When `UponJustifiedPrePrepare` fires and calls `d.NewTimer(round)`, if the current time is past `slotStart + 6s`, the timer fires **immediately** with a zero or negative duration. Both `compareErr` and `timerChan` are ready simultaneously, and Go's `select` picks randomly — causing a ~50% spurious timeout rate for any pre-prepare arriving after the doubled deadline.

### The Trigger

The DNS outage on 2026-03-09 disrupted Obol infrastructure for ~20 minutes (relay endpoints, Prometheus remote write). The global attester timeout rate jumped from ~100/h to ~2,700/h immediately after.

**Note**: Post-incident analysis of `p2p_ping_latency_secs` shows p2p latency was **unchanged** across the inflection point (p50 ~27ms, p99 ~400ms globally, flat throughout). Consensus duration p50 was also flat at ~130-150ms. The direct p2p TCP connections between peers were not affected by the DNS outage.

The exact mechanism by which the DNS outage triggered the latent race condition is **not fully understood**. Possible hypotheses:
- Nodes that reconnected after the outage may have had a brief period of goroutine scheduling pressure (reconnection storms, buffered message replay) that caused some pre-prepares to arrive marginally later
- The Prometheus remote write failure may have caused backpressure affecting goroutine scheduling
- The correlation with the DNS outage may be coincidental, and an unrelated change (e.g., Lighthouse v8.1.2 beacon node release around the same time) may have contributed

Regardless of the trigger, the race condition is deterministic: any pre-prepare arriving after `slotStart + 6s` has a ~50% chance of spurious timeout.

### Why It Was Self-Sustaining

The timeout rate stabilised at ~2,700/h and neither grew nor decayed over 36+ hours. This is because:

- The race condition triggers whenever a pre-prepare arrives after the doubled timer deadline — this is a function of the normal distribution of message timing, not a feedback loop
- No positive feedback loop (timeouts don't cause more timeouts for the same duty)
- Whatever shifted the timing distribution past the threshold was persistent (not a transient backlog that drains)

## Fix

### Immediate (v1.9.2-rc1)

As an immediate mitigation, the `compare()` function and the Compare mechanism were temporarily removed from the QBFT package in v1.9.2-rc1 (commit `e8a3ef5c`). This eliminates the race condition by removing the code path entirely:

- Removed `C` type parameter from `Definition`, `Transport`, `Msg`, `Run`
- Removed `compare()` function, `errCompare`, `errTimeout`, `compareFailureRound`
- Removed `Compare` callback from `Definition`
- Removed `ValueSource()` from `Msg` interface
- Removed `VerifyCh` from consensus instance IO
- Removed `attestationChecker` and `supportedCompareDuties`
- `UponJustifiedPrePrepare` now directly broadcasts `MsgPrepare` without calling Compare

**13 files changed, -633 lines.** All existing tests pass.

**This removal is temporary.** The chain-split-halt / Compare mechanism is a desired safety feature and will be re-introduced with the race condition fixed (see permanent fix below).

### Permanent Fix (for re-introduction of Compare)

When Compare is re-added, the `compare()` function must prioritise `compareErr` over `timerChan` in the `select` to prevent the race:

```go
case <-timerChan:
    // Check if Compare already completed before declaring timeout.
    // With eager absolute-deadline timers, timerChan may fire immediately
    // (zero duration) when the deadline is already past. If d.Compare has
    // also completed, Go's select picks randomly. Priority-check compareErr
    // first to avoid spurious timeouts.
    select {
    case err := <-compareErr:
        if err != nil {
            return inputValueSource, errCompare
        }
        return inputValueSource, nil
    default:
        return inputValueSource, errTimeout
    }
```

This was tested on a branch off `v1.9.1` (`fix/qbft-compare-timer-race`) and all tests pass.

## Detection Gaps

### What made this hard to find

1. **Misleading BN latency correlation**: One peer (`plain-garden`) had elevated `attestation_data` p50 latency (~160ms vs 5ms on other peers). This initially looked like the root cause. Historical analysis showed this was a pre-existing condition on that operator's beacon node, unrelated to the inflection point — BN latency was 5ms throughout the period when timeouts spiked.

2. **`compareAttestations` assumed enabled**: The log message "timeout waiting for local data, used for comparing with leader's proposed data" strongly implies the Compare feature is active. It took explicit verification via Prometheus feature flag metrics to confirm it was disabled on all affected clusters, revealing the race condition theory.

3. **Existing tooling was proposal-focused**: The `missed-proposal` skill only analysed proposer duties. A new `qbft-debug` skill and script were built during this investigation to query Loki for compare timeouts, correlate with BN call performance, and analyse consensus outcomes.

## Planned Permanent Remediations

### Short-term

- [x] Ship v1.9.2 with Compare mechanism temporarily removed (eliminates the race condition)
- [ ] Upgrade affected clusters — prioritise nodes on v1.9.1 (have the bug, easy upgrade path), v1.8.2 nodes are less affected

### Medium-term

- [ ] **Early consensus termination**: When a QBFT instance can't reach quorum (peers have decided and left), it currently spirals through rounds until the 25s hard deadline. Implement deadliner-based context cancellation so expired duties exit immediately rather than burning CPU and p2p bandwidth on futile round changes.

- [ ] **Drop expired duty messages at p2p layer**: `ParSigDB.StoreExternal` processes all incoming partial signatures including for expired duties. Add a fast-path check at the p2p handler or parsigdb level to reject messages for duties past their deadline without acquiring the mutex or logging.

- [ ] **Mitigate post-restart partial signature replay storm**: When a node restarts, peers re-send buffered partial signatures for recent duties. The restarted node's empty `ParSigDB` accepts the first copy and then processes thousands of duplicates synchronously, each acquiring `db.mu` and logging at debug level. This burst (~9,000 messages/min observed, lasting ~2 minutes) blocks goroutine scheduling and causes consensus timeouts during the restart window. Fixes should include:
  - Deduplicating or rate-limiting incoming parsig messages during the replay window
  - Dropping messages for duties that have already expired per the deadliner
  - Making `ParSigEx.handle()` async (see below)

- [ ] **Async parsig processing**: `ParSigEx.handle()` calls subscribers synchronously (noted as `TODO(corver): Call this async` in the code). Making this async with a bounded channel would prevent p2p message floods from blocking handlers.

### Long-term

- [ ] **Consensus health monitoring**: Add metrics for round progression (how many rounds before decision), quorum reachability (can this node reach quorum given known peer states), and Compare callback latency. These would have surfaced the issue faster.

- [ ] **Deterministic timer safety**: Any future use of absolute-deadline timers in combination with `select` statements should use priority receives (nested select with default) to prevent the Go `select` non-determinism from causing spurious timeouts.

## Lessons Learned

1. **Go `select` non-determinism is a real hazard with absolute timers.** When a timer channel can fire immediately (zero/negative duration), it races with other ready channels. This is a class of bug that's invisible in testing (timers are always relative in tests) and only manifests in production with real clock alignment.

2. **Disabled code paths still execute.** The Compare mechanism was effectively a no-op (`compareAttestations=false` everywhere), but its `select` loop still ran on every `UponJustifiedPrePrepare` event. Features gated by runtime flags still need their code paths to be correct.

3. **Infrastructure outages can trigger latent bugs.** The DNS outage didn't cause the bug — it correlated with the onset of symptoms. The exact trigger mechanism is not fully understood, but the race condition existed since the Compare mechanism was introduced and could be triggered by any change affecting pre-prepare delivery timing.
