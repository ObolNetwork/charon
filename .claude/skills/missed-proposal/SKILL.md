```skill
---
name: missed-proposal
description: Analyze a potentially missed block proposal for a cluster at a specific slot
user-invokable: true
---

# Missed Proposal Analysis

Analyze a potentially missed block proposal by collecting cluster configuration, consensus leader information, and event logs from the specified slot. This skill gathers data and performs root cause analysis.

## Arguments

The user must provide:
- **cluster name** (required): e.g. `Lido x Obol: Ethereal Elf`
- **slot number** (required): e.g. `13813408`
- **network** (optional, default: `mainnet`): e.g. `mainnet`, `hoodi`, `sepolia`

## Execution

Run the Python script to collect all data:
```bash
python3 scripts/debug/missed_proposal.py "<cluster_name>" <slot> [network]
```

The script outputs JSON with:
- `slot`: slot number, epoch, timestamp, time (UTC)
- `cluster`: cluster config (name, hash, version, operators, threshold, validators, peers)
- `cluster_found`: boolean indicating if cluster was found in Prometheus
- `leaders`: expected consensus leaders for rounds 1, 2, 3
- `logs`: parsed log events from Loki with warnings
- `inclusion_metric`: "missed", "not_missed", or "unknown"

## Handling Warnings

The script may report warnings that require user action:

### No Logs Available
If `logs.warnings` contains "No log streams found" or `logs.total_entries` is 0:
- Inform the user that no logs are available for this slot
- This could mean: logs have been rotated, the cluster didn't have this duty, or the cluster name is incorrect

### Missing Peer Logs
If `logs.warnings` contains "Missing logs from peers":
- Report which peers are missing logs
- Explain that complete analysis may not be possible without all peer logs
- Ask the user if they can request logs from the missing operators

### Cluster Not Found
If `cluster_found` is false:
- Report that the cluster was not found in Prometheus
- Suggest double-checking the cluster name spelling and network

## Analysis and Output

After collecting data, analyze and present findings in this format:

### 1. Cluster Info
Present cluster configuration:
```
=== Cluster Info ===
Name:       <cluster_name>
Hash:       <cluster_hash>
Version:    <version>
Network:    <network>
Nodes:      <operators> (threshold: <threshold>)
Validators: <active> active / <total> total
```

### 2. Slot Info
Present slot details:
```
=== Slot Info ===
Slot:       <slot>
Epoch:      <epoch> (slot <slot_in_epoch> of 32)
Time:       <UTC time>
Duty:       proposer
```

### 3. Expected Consensus Leaders
Present the leader table:
```
=== Expected Consensus Leaders ===
Round 1:    <peer_name> (index <index>)
Round 2:    <peer_name> (index <index>)
Round 3:    <peer_name> (index <index>)
```

### 4. Event Timeline
Present key events chronologically with offset from slot start:
```
=== Event Timeline ===
(Offset relative to slot start time: <UTC time>)

  +0.005s  [SCHED]    Slot started
  +0.010s  [SCHED]    Resolved proposer duty (vidx=..., pubkey=...)
  +0.015s  [FETCHER]  BN call start: <endpoint> [<peer>]
  ...
```

Event types to show:
| Type | Tag | Description |
|------|-----|-------------|
| slot_ticked | SCHED | Slot started |
| resolved_duty | SCHED | Duty assigned to validator |
| bn_call_start | FETCHER | Fetching unsigned data from BN |
| bn_call_done | FETCHER | BN call completed with RTT |
| bn_call_slow | FETCHER | BN call took longer than expected |
| consensus_started | QBFT | Consensus instance started |
| round_timeout | QBFT | Round timed out, moving to next |
| consensus_decided | QBFT | Consensus decision reached |
| block_proposal_received | VAPI | VC submitted block proposal |
| threshold_reached | SIGAGG | Threshold signatures aggregated |
| broadcast_success | BCAST | Block broadcast to BN |
| broadcast_timeout | BCAST | Duty expired before broadcast |
| sse_block_gossip_late | SSE | Late block gossip event |
| sse_block_late | SSE | Late block event |
| tracker_all_participated | TRACKER | All peers participated |
| tracker_partial_participation | TRACKER | Some peers missing |
| tracker_block_included | TRACKER | Block included on-chain |
| tracker_block_missed | TRACKER | Block NOT included on-chain |
| error | ERROR | Error message from a peer |

### 5. Summary
Provide analysis summary:

**Consensus Status:**
- Did consensus complete? In which round?
- Were there round timeouts? Which leaders failed?

**Block Type:**
- Was it a blinded or unblinded block?

**Broadcast Status:**
- Was the block successfully broadcast?
- What was the broadcast delay range?

**BN Call Performance:**
- What was the RTT range across peers?
- Were there any slow BN calls?

**Inclusion Status:**
- Was the block included on-chain? (from logs or metric)
- If missed, what was the broadcast delay?

**Participation:**
- Did all peers participate?
- Which peers were absent?

**Errors:**
- List any errors per peer

### 6. Root Cause Analysis

Based on the data, provide a root cause analysis:

**Common failure patterns:**

1. **Leader failure in round 1**
   - Round 1 leader did not propose
   - Check if leader had connectivity issues or slow BN

2. **Slow beacon node calls**
   - High RTT on BN calls across peers
   - May cause consensus to start late

3. **Consensus timeout without decision**
   - All rounds timed out
   - Network connectivity issue between peers

4. **Broadcast too late**
   - Block was broadcast but with high delay (>4s)
   - Block may have been included but orphaned

5. **Partial participation**
   - Some peers didn't participate
   - Check if absent peers had logs at all

6. **Block missed despite successful broadcast**
   - Block was broadcast on time but not included
   - May indicate relay/builder issues for MEV blocks

## Example Usage

User: "Analyze missed proposal for cluster 'Lido x Obol: Ethereal Elf' at slot 13813408"

1. Run the script
2. Parse JSON output
3. Present cluster info, leaders, timeline
4. If block was missed, identify likely root cause
5. If data is incomplete, inform user what additional data is needed

## Dependencies

- `python3` (standard library only)
- `OBOL_GRAFANA_API_TOKEN` environment variable must be set
- Access to Grafana datasources (Prometheus and Loki)
```
