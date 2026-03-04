---
name: duty-timeline
description: Generate a comprehensive timeline of events for a duty across all peers
user-invokable: true
---

# Duty Timeline

Generate a detailed timeline showing the complete lifecycle of a validator duty (block proposal, attestation, etc.) across all cluster peers by analyzing Loki logs. Shows **per-peer details** for key events like BN calls, broadcasts, and errors to support root cause analysis.

## Arguments

The user must provide:
- **cluster name** (required): e.g. `Lido x Obol: Ethereal Elf`
- **slot number** (required): e.g. `13813408`
- **network** (optional, default: `mainnet`): e.g. `mainnet`, `hoodi`
- **duty type** (optional, default: `proposer`): e.g. `proposer`, `attester`, `randao`, `sync_message`, `aggregator`

## Execution

Run the script with the required arguments:
```bash
bash scripts/duty-timeline.sh "<cluster_name>" <slot> [network] [duty_type]
```

## What It Does

1. Calculates expected consensus leaders for rounds 1, 2, and 3
2. Queries Loki for all logs related to the duty across the time window
3. Parses logs with Python (handles nanosecond timestamps correctly)
4. Shows timing offset relative to slot start for each event
5. Displays **per-peer rows** for events where peer-level detail matters
6. Tracks events across all workflow components:
   - Scheduler: slot ticks, duty resolution
   - Fetcher: beacon node calls per peer with RTT
   - QBFT: consensus start, round changes, decisions
   - ValidatorAPI: block/blinded block proposals per peer
   - SigAgg: threshold signature aggregation per peer
   - Broadcast: submission per peer with delay
   - SSE: block_gossip/block/head events, "too late" warnings per peer
   - Tracker: participation and inclusion status
   - Errors: consensus timeout / permanent failure per peer

## Key Events Tracked

| Component | Event | Per-peer? | Meaning |
|-----------|-------|-----------|---------|
| SCHED | Slot ticked | first | Slot started |
| SCHED | Resolved duty | first per pubkey | Duty assigned to validator |
| FETCHER | BN call start | yes | Fetching unsigned duty data |
| FETCHER | BN call done | yes | Data fetched (with RTT) |
| FETCHER | SLOW BN call | yes | Call took longer than expected |
| QBFT | Consensus started | first | QBFT instance initialized |
| QBFT | Round TIMEOUT | first per round | Round failed, moving to next |
| QBFT | Consensus DECIDED | first | Agreement reached |
| VAPI | Block proposal received | yes | VC submitted unblinded proposal |
| VAPI | Blinded block received | yes | VC submitted blinded proposal |
| SIGAGG | Threshold reached | yes | Enough partial sigs collected |
| BCAST | Broadcast SUCCESS | yes | Submitted to beacon node (with delay) |
| BCAST | TIMEOUT | yes | Duty expired before broadcast |
| SSE | block_gossip TOO LATE | yes | Late gossip event per peer |
| SSE | block event TOO LATE | yes | Late block event per peer |
| SSE | SSE block gossip/head/block event | first | Normal SSE events |
| TRACKER | All peers participated | first | Full participation |
| TRACKER | Not all peers participated | first | Some peers missing |
| TRACKER | BLOCK MISSED | first | Block never included on-chain |
| TRACKER | BLINDED BLOCK MISSED | first | Blinded block never included |
| ERROR | consensus timeout | yes | Per-peer consensus timeout |
| ERROR | permanent failure | yes | Per-peer permanent failure |

## Output

The script provides:

1. **Duty Info**: slot, epoch, time, network, duty type
2. **Expected Consensus Leaders**: who should lead rounds 1, 2, 3
3. **Event Timeline**: chronological sequence with timing offsets and per-peer detail
4. **Summary**:
   - Consensus status (success/failure, round count)
   - Block type (blinded/unblinded)
   - Broadcast status with delay range (min-max across peers)
   - BN call RTT range across peers
   - Inclusion status (for proposer duties, with broadcast_delay)
   - Participation status (with absent peers listed)
   - Error summary per peer

### Example Output

```
=== Duty Info ===
Slot:       13810452
Epoch:      431576 (slot 20 of 32)
Time:       2026-03-03T21:31:00Z
Network:    mainnet
Duty:       proposer

=== Expected Consensus Leaders ===
Round 1:    curious-cat (index 2)
Round 2:    daring-dog (index 3)
Round 3:    eager-elk (index 4)

=== Fetching Logs ===
Found 87 log entries

=== Event Timeline ===
(Offset relative to slot start time: 2026-03-03T21:31:00Z)

  +0.005s  [SCHED]    Slot 13810452 started
  +0.010s  [SCHED]    Resolved proposer duty (vidx=123456, pubkey=0x...)
  +0.015s  [FETCHER]  BN call start: /eth/v3/validator/blocks/13810452 [alpha-ant]
  +0.016s  [FETCHER]  BN call start: /eth/v3/validator/blocks/13810452 [brave-bee]
  +0.018s  [FETCHER]  BN call start: /eth/v3/validator/blocks/13810452 [curious-cat]
  +0.920s  [FETCHER]  BN call done:  /eth/v3/validator/blocks/13810452 [alpha-ant] (RTT=0.9s)
  +1.800s  [FETCHER]  BN call done:  /eth/v3/validator/blocks/13810452 [brave-bee] (RTT=1.8s)
  +2.100s  [FETCHER]  SLOW BN call:  /eth/v3/validator/blocks/13810452 [curious-cat] (RTT=2.1s)
  +2.110s  [QBFT]     Consensus started
  +6.200s  [QBFT]     Round 1 TIMEOUT -> Round 2
                       Reason: leader not proposing
  +8.500s  [QBFT]     Consensus DECIDED in round 2
                       Leader: daring-dog (index 3)
  +8.600s  [VAPI]     Blinded block received [alpha-ant] (version=deneb)
  +8.620s  [VAPI]     Blinded block received [brave-bee] (version=deneb)
  +8.900s  [SIGAGG]   Threshold reached [alpha-ant] (submit_blinded_block)
  +8.920s  [SIGAGG]   Threshold reached [brave-bee] (submit_blinded_block)
  +9.000s  [BCAST]    Broadcast SUCCESS [alpha-ant] (delay=3.5s)
  +9.020s  [BCAST]    Broadcast SUCCESS [brave-bee] (delay=3.52s)
  +9.100s  [SSE]      block_gossip TOO LATE [alpha-ant] (delay=9.1s)
  +9.150s  [SSE]      block event TOO LATE [brave-bee] (delay=9.15s)
  +12.00s  [ERROR]    consensus timeout [average-road]
  +480.0s  [TRACKER]  BLINDED BLOCK MISSED: never included on-chain
                       Pubkey: 0x..., Broadcast delay: 3.5s
  +480.1s  [TRACKER]  Not all peers participated
                       Absent: average-road

=== Summary ===
Consensus:     Completed in round 2 after 1 timeout(s)
               Leader: daring-dog (index 3)
               Round 1 leader curious-cat failed
Block type:    blinded
Broadcast:     Successfully submitted (delay range: 3.5s-3.5s)
BN call RTT:   0.9s-2.1s across 3 peers
Inclusion:     MISSED - block never included on-chain (broadcast_delay=3.5s)
Participation: Not all peers participated (absent: average-road)
Errors:
  - [average-road] consensus timeout
```

## Common Failure Patterns

### Slow Beacon Node (per-peer)
```
  +0.920s  [FETCHER]  BN call done:  /eth/v3/...  [alpha-ant] (RTT=0.9s)
  +2.100s  [FETCHER]  SLOW BN call:  /eth/v3/...  [curious-cat] (RTT=2.1s)
```
Shows which specific peers have slow BN calls and the RTT spread.

### Consensus Timeouts
```
  +6.200s  [QBFT]     Round 1 TIMEOUT -> Round 2
                       Reason: leader not proposing
```
Round 1 leader failed to propose, consensus moved to round 2.

### Missed Block with Broadcast Delay
```
  +480.0s  [TRACKER]  BLINDED BLOCK MISSED: never included on-chain
                       Pubkey: 0x..., Broadcast delay: 3.5s
```
Block was broadcast but not included on-chain. Summary includes broadcast_delay for correlation.

### Per-peer Errors
```
  +12.00s  [ERROR]    consensus timeout [average-road]
```
Shows which peer(s) experienced errors, helping identify the failing node.

## Troubleshooting

If no logs are found:
- Verify the cluster name spelling is exact
- Check the network is correct
- Confirm the slot had a duty (not all slots have all duty types)
- Logs may have been rotated if the slot is old

## Dependencies

This skill uses:
- `cluster-config.sh` - to get cluster info and peer names
- `grafana-datasources.sh` - to discover Loki URL
- Loki API - to query logs
- `python3` - to parse Loki JSON (handles nanosecond timestamps)
- Requires `OBOL_GRAFANA_API_TOKEN` environment variable
