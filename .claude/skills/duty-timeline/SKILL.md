---
name: duty-timeline
description: Generate a comprehensive timeline of events for a duty across all peers
user-invokable: true
---

# Duty Timeline

Generate a detailed timeline showing the complete lifecycle of a validator duty (block proposal, attestation, etc.) across all cluster peers by analyzing Loki logs.

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
3. Parses and sorts events chronologically
4. Shows timing offset relative to slot start for each event
5. Tracks events across all workflow components:
   - Scheduler: slot ticks, duty resolution
   - Fetcher: beacon node calls and latency
   - QBFT: consensus start, round changes, decisions
   - ValidatorAPI: block proposals received
   - SigAgg: threshold signature aggregation
   - Broadcast: submission to beacon node
   - Tracker: participation and inclusion status

## Key Events Tracked

| Component | Event | Meaning |
|-----------|-------|---------|
| SCHED | Slot ticked | Slot started |
| SCHED | Resolved duty | Duty assigned to validator |
| FETCHER | Calling beacon node | Fetching unsigned duty data |
| FETCHER | Beacon node call finished | Data fetched successfully |
| FETCHER | SLOW beacon node call | Call took longer than expected |
| QBFT | Consensus started | QBFT instance initialized |
| QBFT | Round TIMEOUT | Round failed, moving to next |
| QBFT | Consensus DECIDED | Agreement reached |
| VAPI | Block proposal received | VC submitted proposal |
| SIGAGG | Threshold signatures aggregated | Enough partial sigs collected |
| BCAST | Broadcast SUCCESS | Submitted to beacon node |
| BCAST | TIMEOUT | Duty expired before broadcast |
| TRACKER | All peers participated | Full participation |
| TRACKER | Not all peers participated | Some peers missing |
| TRACKER | BLOCK MISSED | Block never included on-chain |

## Output

The script provides:

1. **Duty Info**: slot, epoch, time, network, duty type
2. **Expected Consensus Leaders**: who should lead rounds 1, 2, 3
3. **Event Timeline**: chronological sequence with timing offsets
4. **Summary**:
   - Consensus status (success/failure, round count)
   - Broadcast status (success/timeout)
   - Inclusion status (for proposer duties)
   - Participation status

### Example Output

```
=== Duty Info ===
Slot:       13813408
Epoch:      431669 (slot 0 of 32)
Time:       2026-03-04T00:41:36Z
Network:    mainnet
Duty:       proposer

=== Expected Consensus Leaders ===
Round 1:    peer0 (index 0)
Round 2:    peer1 (index 1)
Round 3:    peer2 (index 2)

=== Event Timeline ===
(Offset relative to slot start time: 2026-03-04T00:41:36Z)

  +0.005s  [SCHED]    Slot 13813408 started
  +0.010s  [SCHED]    Resolved proposer duty (vidx=123456, pubkey=0x...)
  +0.015s  [FETCHER]  Calling beacon node: /eth/v3/validator/blocks/13813408
  +0.150s  [FETCHER]  Beacon node call finished: /eth/v3/validator/blocks/13813408
  +0.155s  [QBFT]     Consensus started
  +1.200s  [QBFT]     ✓ Consensus DECIDED in round 1
                      Leader: peer0 (index 0)
  +1.500s  [SIGAGG]   ✓ Threshold signatures aggregated
  +1.600s  [BCAST]    ✓ Broadcast SUCCESS (delay=1.6s)
  +8.000s  [TRACKER]  ✓ All peers participated

=== Summary ===
Consensus:  ✓ Completed in round 1 (optimal)
Broadcast:  ✓ Successfully submitted to beacon node
Inclusion:  ✓ Block included on-chain
Participation: ✓ All peers participated
```

## Common Failure Patterns

### Slow Beacon Node
```
  +2.500s  [FETCHER]  ⚠️  SLOW beacon node call: /eth/v3/validator/blocks/...
```
Indicates the beacon node took too long to respond, potentially causing downstream timeouts.

### Consensus Timeouts
```
  +4.000s  [QBFT]     ⚠️  Round 1 TIMEOUT -> Round 2
                      Reason: leader not proposing
```
Round 1 leader failed to propose, consensus moved to round 2.

### Missed Block
```
  +480.0s  [TRACKER]  ❌ BLOCK MISSED: never included on-chain
                      Pubkey: 0x..., Broadcast delay: 3.5s
```
Block was broadcast but not included on-chain (possibly late or network issues).

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
- Requires `OBOL_GRAFANA_API_TOKEN` environment variable
