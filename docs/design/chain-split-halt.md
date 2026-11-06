# Design: polishing `chain_split_halt`

| | |
|---|---|
| Status | Draft for discussion |
| Feature | `chain_split_halt` (`app/featureset`, currently `alpha`) |
| Trigger | dvt-c3 (Hoodi) halted through a 2/2 fork split on 2026-10-26 |
| Reviewers | @KaloyanTanev |

## TL;DR

`chain_split_halt` did its job on its first real chain split. During the cancelled Hoodi Gloas fork, dvt-c3 split 2/2 across forks. The cluster stopped signing at the first fork slot. **No key share signed a single attestation on the abandoned branch.** Signing resumed on its own once a third node had both its beacon node and its validator client upgraded. The total cost was about 61 minutes of missed attestations.

The safety held, but the operator experience did not. For 61 minutes:
- every node reported `readyz=1`;
- the only health check that fired pointed at MEV relays and peer latency;
- duties failed as generic `no_consensus` or as `bug_*` reasons;
- the logs never said "chain split" or "fork mismatch", nor what to do.

This doc proposes changes to make the halt **legible** (operators know it happened and why) and **actionable** (they know what to fix, and when it's resolved). It also proposes **pre-emptive** detection: peers warn days before a fork that they disagree on the schedule. Head-vote mismatches stay out of scope. They are deliberate (see [Non-goals](#non-goals)).

## Background: what the feature does today

With `--feature-set-enable=chain_split_halt`, the QBFT `Compare` hook (`core/consensus/qbft/qbft.go`) runs for attester duties. When a justified PRE-PREPARE arrives, the node waits for its own fetched attestation data. It then refuses to PREPARE if the leader's value differs from its own on any of:

- source epoch / root;
- target epoch / root;
- the attester duty (committee, index, and so on);
- a validator in the leader's set for which this node has no duty (e.g. stale shuffling).

On mismatch, `compare` returns `errCompare` and `compareFailureRound` is set. The node does not PREPARE, so the round times out and changes. The leader's `beacon_block_root` (head vote) is **not** compared.

The net effect is that a threshold of nodes must independently agree on the FFG checkpoints before anything is decided. Without the flag, any leader's view is imposed on all nodes. With it, the cluster only signs checkpoints that `t` of `n` independent beacon nodes agree on.

Current usage, from Obol central monitoring over 7 days: 12 clusters (8 mainnet, 4 Hoodi). dvt-c3's attester success rate in the 7 days before the incident was 99.91% (39 failures / 44,901 duties). That's evidence the flag is cheap in steady state, though one cluster isn't proof. See [Open questions](#open-questions).

## Incident: dvt-c3, Hoodi, 2026-10-26

The Hoodi Gloas fork (epoch 132352, 17:42:48 UTC) was postponed at ACDE #248. Clients shipped "unschedule" releases. dvt-c3 (4 nodes, threshold 3, 73 active validators, ~50k test ETH) had two nodes on pre-unschedule releases:

| Node | Beacon node | VC | Side after fork |
|---|---|---|---|
| Node 1 | Teku 26.10.2 | Teku 26.10.2 | Fulu (canonical) |
| Node 2 | Teku 26.10.2 | Teku 26.10.2 | Fulu (canonical) |
| Node 3 | Lighthouse 8.3.1 | Teku 26.10.1 | Gloas (dead branch) |
| Node 4 | Teku 26.10.1 | Teku 26.10.1 | Gloas (dead branch) |

All four ran charon v2.0.0-rc2 with `chain_split_halt`, `fetch_att_on_block` and `quic`.

Timeline (UTC). The source is metrics only; this cluster does not ship logs to Obol Loki.

| Time | Event | Evidence |
|---|---|---|
| 17:42:48 | Fork epoch 132352 starts | |
| 17:43 | Attester consensus decisions and broadcasts drop to 0 on all four nodes | `core_consensus_duration_seconds_count`, `core_bcast_broadcast_total` |
| 17:43 | Node 3/4 beacon node heads freeze at slot 4235263 (last pre-fork slot); their BN peer counts drop from ~150–200 to ~15–35 | `app_beacon_node_sse_head_slot`, `app_beacon_node_peers` |
| ~17:44 | charon on node 3/4 applies the Gloas schedule from its beacon node | `app_fork_current_activation_epoch{fork="gloas"}` |
| 17:44 / 17:50 | Only health check to fire: `insufficient_round_changes` (node 3/4 at 17:44, node 1/2 at 17:50) | `app_health_checks` |
| 17:58 | First tracker failures (`no_consensus`), about 15 min after the halt | `core_tracker_failed_duty_reasons_total` |
| ~18:28 | Node 3 beacon node upgraded to Lighthouse 8.3.2; it rejoins the canonical head by 18:32 | `app_beacon_node_version`, head slot |
| ~18:35–18:44 | Consensus decides again with 3 nodes, but duties fail with `insufficient_peer_signatures`. This is consistent with node 3's VC still on Teku 26.10.1, signing with the Gloas fork domain | tracker reasons; VC user agent changes to 26.10.2 afterwards |
| 18:44 | Attestations resume (3 of 4 nodes) | broadcasts |
| 18:49 | Node 4 (Teku 26.10.2) rejoins; all 4 nodes are signing | broadcasts, head slot |

charon needed **no restart**. `app/forkschedule` refreshes every minute and reverted to the Fulu schedule once the beacon nodes did.

### What went right

1. **No decision was reached on any branch while the split lasted**, so no VC was ever served attestation data and no key share signed anything. Without the flag, every node would have accepted whichever leader's value came first. Half the rounds were led by a Gloas-side node, so the Fulu-side VCs would have signed dead-branch checkpoints, and the reverse also applies. Different signing domains would probably still have prevented an aggregate. But all four VCs' slashing-protection DBs would hold target votes for epochs 132352+ on a dead branch. Those VCs would then refuse the canonical votes for the same epochs as double votes, which extends the outage. This is the Holesky failure mode in miniature ([post-mortem](https://github.com/ethereum/pm/blob/master/Network-Upgrade-Archive/Pectra/holesky-postmortem.md)).
2. **Recovery was automatic and needed no slashing-DB surgery.** Upgrading the clients was enough.
3. **There was no false halt beforehand.** Steady-state failure rates were unaffected.

### What was rough

| # | Symptom | Why it hurts |
|---|---|---|
| R1 | `readyz=1` on every node for the full 61 min | Dashboards and alerting showed the cluster as healthy. `bnFarBehindSlots=320` (64 min) would have tripped about 3 min after recovery. |
| R2 | The only health check was `insufficient_round_changes`, whose description blames late payloads, peer latency and MEV relays | It sends the operator the wrong way. |
| R3 | Attester failures appear as `no_consensus`, indistinguishable from a network fault | There's no signal that the cluster *chose* not to sign. |
| R4 | `bug_fetch_error` on `payload_attestation` and `sync_contribution` | Operators will file charon bugs for a client-configuration problem. |
| R5 | No metric for compare failures; it's only a per-round `log.Warn("compare leader value with local value failed")` with full leader and local data dumps | It can't be graphed or alerted on, and it's noisy and unexplained in logs. |
| R6 | Nothing told the cluster, before the fork, that two peers' beacon nodes would fork | There were days of lead time, and it was detectable (`app/forkschedule` already sees conflicts between a node's own beacon nodes, but not across peers). |
| R7 | Nothing told node 3 that its **VC** was still on the old schedule after its beacon node was fixed | That cost about 10 extra minutes (`insufficient_peer_signatures`). |
| R8 | Tracker failures arrive about 15 min late | Alerts on `core_tracker_*` fire long after the halt. The real-time signal is decided/broadcast counts. |
| R9 | No "resolved" signal | Operators have to infer recovery from dashboards. |

## Goals

- **G1 Legible.** An operator looking at readyz, health checks, failure reasons, or logs sees "chain split / fork mismatch" within one epoch.
- **G2 Actionable.** Every signal names the disagreeing peers or fields and the likely fix: upgrade or resync the beacon node *and* the VC, and keep the slashing DB.
- **G3 Pre-emptive.** Peers whose fork schedules differ are flagged before the fork.
- **G4 Closed loop.** Explicit "resolved" log and metric, with halt duration.
- **G5 No new liveness risk.** Nothing here changes what the cluster signs.

## Non-goals

- **Comparing the head vote (`beacon_block_root`).** This is deliberate:
  - Head votes are LMD-GHOST votes and are never slashable.
  - Honest beacon nodes regularly disagree on head near slot boundaries (late blocks, reorgs).
  - Halting on head mismatch would turn ordinary propagation jitter into missed attestations.
  - FFG source and target are the slashable surface, and that's what the flag guards.
- Changing QBFT semantics, thresholds, or the timer model.
- Extending the comparison to other duties (proposer, sync committee). That's worth a separate doc.

## Proposals

The priorities are a suggestion; deciding what to build is the point of this doc. Each item lists the signal, the change, and the cost.

### P0-1 Exchange fork schedules via peerinfo (pre-emptive)

- **Change:** add `fork_schedule_hash` to `PeerInfo`, following the `builder_config_hash` pattern in `app/peerinfo/peerinfo.go:294`. Hash the applied `ForkForkSchedule` (sorted fork name → epoch and version, `MaxUint64` for unscheduled).
- **Signals:**
  - `app_peerinfo_fork_schedule_mismatch{peer}` gauge.
  - Rate-limited WARN, e.g. *"Peer node 4's beacon node schedules gloas at epoch 132352, this node's does not. The cluster will halt at that epoch unless the clients agree; check client versions."* Escalate to ERROR within an epoch of the earliest disputed fork.
  - Health check `fork_schedule_mismatch` (severity critical).
- **Why:** this is the one change that would have prevented the incident rather than explained it. It closes R6. The epochs could also be sent instead of a hash, so the log can name the disputed fork; that would cost about 20 bytes per fork.
- **Cost:** small. One proto field, one gauge, one health check. Peers on older versions send no hash, so nothing is compared (same as builder config).

### P0-2 First-class compare-failure signal

- **Change:**
  - Count in `Compare`: `core_consensus_compare_failed_total{duty,field}`, where `field` ∈ `source_epoch|source_root|target_epoch|target_root|duty|missing_duty|local_timeout`.
  - Turn `attestationMismatch` from a concatenated string into a typed set of fields.
- **Logging:** replace the per-round WARN with one ERROR per duty, emitted on the instance's final timeout when any round failed comparison. It should list the fields, the disagreeing leaders and a short remediation, and it should *not* dump the full attestation data at WARN; keep the dumps at DEBUG. For example: *"Refused to sign attestation: leader's target root differs from local beacon node (possible chain split). No signature was produced. Check that all beacon nodes are on the same fork and client versions."*
- **Why:** closes R5 and gives P0-3, P1-1 and P1-2 something to key off.
- **Cost:** small.

### P0-3 Tracker reason `chain_split_halt`

- **Change:** when an attester instance times out and `compareFailureRound` was ever set, report `chain_split_halt` instead of `no_consensus`. Document it in `docs/reasons.md` with remediation.
- **Why:** closes R3, and it's the reason operators and the obol-monitoring skill will see first.
- **Cost:** small, but it needs the compare outcome to reach the tracker, e.g. via the consensus debugger or a new instance-level error type.

### P1-1 readyz state for a halted cluster

- **Change:** add `readyzChainSplit` (next free value) when compare failures persist for one epoch or more, or when P0-1 reports a mismatch on a fork that is currently active.
- **Alternative or addition:** a `readyzBeaconNodeHeadStalled` when the BN head hasn't advanced in N slots (N ≈ 8) while the wall clock has. That catches a beacon node stuck on a dead branch independently of the flag. During the incident, node 3/4 had frozen heads for 61 min, but their sync distance only approached the 320-slot threshold.
- **Why:** closes R1. Most operator alerting keys off readyz.
- **Cost:** small. Note that a new readyz value needs CDVN/LCDVN dashboard mappings.

### P1-2 Health checks: add `chain_split_halt`, fix `insufficient_round_changes`

- **Change:**
  - New critical check driven by `core_consensus_compare_failed_total`, with a description in the style of `app/health/checks.go` that states what happened, why it's safe, and what to do.
  - Amend `insufficient_round_changes` to mention that, with `chain_split_halt` enabled, round changes can be caused by refused comparisons.
- **Why:** closes R2.
- **Cost:** trivial.

### P1-3 Diagnose wrong-domain partial signatures from the local VC

- **Change:** when the local VC's partial signature fails verification, retry verification against the signing domain of the adjacent fork in the BN-reported schedule (previous and next fork version). If that succeeds, log: *"Validator client signed with the gloas fork domain, but the cluster applies fulu. Upgrade or reconfigure the validator client."* Expose it as `core_validatorapi_vc_fork_domain_mismatch_total`.
- **Why:** closes R7. It also covers a VC whose schedule differs from its BN's in any future fork.
- **Cost:** medium. It's an extra verify only on the failure path. A cheaper alternative is to extend `app_fork_readiness{component="validator_client"}` from user-agent heuristics to an explicit *"this VC version schedules fork X at epoch Y"* table. That's lower fidelity and needs per-release maintenance.

### P1-4 Stop reporting `bug_fetch_error` for fork-split fetch failures

- **Change:** investigate which BN errors surfaced as `bug_fetch_error` for `payload_attestation` and `sync_contribution` (probably unknown block roots, or a fork-version mismatch on a dead-branch beacon node). Classify them as BN errors, or as `chain_split_halt` when P0-1/P0-2 says a split is in progress.
- **Why:** closes R4.
- **Cost:** needs a log sample. dvt-c3 doesn't ship logs; we can ask Bitcoin Suisse for the 17:40–18:50 UTC window, or reproduce in kurtosis (see [Testing](#testing)).

### P1-5 "Resolved" signal

- **Change:** on the first successful compare for an attester duty after ≥1 epoch of compare failures, log INFO with the halt duration in slots and minutes, and set a `core_consensus_chain_split_halt_last_duration_seconds` gauge.
- **Why:** closes R9 and makes post-incident reporting trivial.
- **Cost:** trivial.

### P2-1 Operator runbook

- **Change:** add a docs.obol.org page, "My cluster halted with chain_split_halt", linked from every log and health check above:
  1. Identify the disagreeing nodes (metric or log).
  2. Upgrade or resync **both** the beacon node and the VC on those nodes.
  3. **Do not delete the slashing-protection DB.** The halt kept it clean, and deleting it is the dangerous step.
  4. Watch for the "resolved" log.

### P2-2 Real-time alert guidance

- **Change:** add a CDVN/LCDVN Grafana alert on `rate(core_consensus_duration_seconds_count{duty="attester"}[5m]) == 0` while validators are active. Document that `core_tracker_*` lags by about 2 epochs.
- **Why:** closes R8 without changing tracker timing.

### P2-3 Graduation path

Once P0-x land, decide whether to promote `chain_split_halt` to `beta`, and later to `stable` (default on). The trade-off:

| Default on | Default off |
|---|---|
| Every cluster gets the Holesky-class protection | No new liveness risk from target disagreements at epoch boundaries |
| Risk of false halts if beacon nodes disagree on the target near the first slot of an epoch (late epoch-boundary block). `fetch_att_on_block` mitigates this. | Clusters that most need it (mixed clients, slow upgrade discipline) won't turn it on |

We need fleet data before deciding: compare-failure rate in steady state (needs P0-2's metric), split by BN client mix.

## Testing

- **Unit:** typed mismatch fields; tracker reason mapping; peerinfo hash equality and the older-peer case.
- **Kurtosis:** a 4-node cluster where two beacon nodes get a different fork epoch in their config. Assert:
  - the mismatch gauge fires before the fork;
  - the reason is `chain_split_halt` after it;
  - readyz moves to the new state;
  - "resolved" is logged after the configs are aligned and the beacon nodes restarted.
- **Compose:** re-run the scenario with mixed VC versions to exercise P1-3.

## Open questions

1. Hash vs. explicit epochs in peerinfo (log quality vs. message size and stability)?
2. Should P0-1 count as a mismatch when *this* node's own beacon nodes disagree? `app/forkschedule` already picks the earliest scheduled epoch across them.
3. Is one epoch the right persistence threshold for readyz and the health check, or should it be two to avoid boundary flaps?
4. P1-3: is a failure-path retry against adjacent fork domains acceptable, or should it stay heuristic?
5. Should we ask Bitcoin Suisse for dvt-c3 logs to pin down R4 before implementing P1-4?
6. Graduation criteria for `beta` and `stable`.

## Appendix: queries

The source is Obol Grafana, datasource `obol-prometheus-ds`, selector `{cluster_name="dvt-c3",cluster_network="hoodi"}`:

```promql
# Real-time halt / resume
sum by (nickname) (increase(core_bcast_broadcast_total{duty="attester"}[1m]))
# Dead-branch beacon nodes
max by (nickname) (app_beacon_node_sse_head_slot)
# Applied fork per node
max by (nickname, fork) (app_fork_current_activation_epoch)
# What operators saw
max by (nickname, name) (app_health_checks) > 0
app_monitoring_readyz
sum by (duty, reason) (increase(core_tracker_failed_duty_reasons_total[3m])) > 0
```
