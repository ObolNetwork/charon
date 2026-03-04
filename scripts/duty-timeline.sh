#!/usr/bin/env bash
# Generates a comprehensive timeline of events for a duty across all peers.
# Requires OBOL_GRAFANA_API_TOKEN environment variable.
# Usage: bash scripts/duty-timeline.sh <cluster_name> <slot> [network] [duty_type]
#   cluster_name: e.g. "Lido x Obol: Ethereal Elf"
#   slot: slot number (e.g. 13813408)
#   network: mainnet (default), hoodi, sepolia, etc.
#   duty_type: proposer (default), attester, randao, etc.

set -euo pipefail

CLUSTER_NAME="${1:-}"
SLOT="${2:-}"
NETWORK="${3:-mainnet}"
DUTY_TYPE="${4:-proposer}"

if [ -z "$CLUSTER_NAME" ] || [ -z "$SLOT" ]; then
  echo "Error: cluster name and slot are required" >&2
  echo "Usage: bash scripts/duty-timeline.sh <cluster_name> <slot> [network] [duty_type]" >&2
  exit 1
fi

if [ -z "${OBOL_GRAFANA_API_TOKEN:-}" ]; then
  echo "Error: OBOL_GRAFANA_API_TOKEN is not set" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Duty type name to numeric value mapping (from core/types.go)
declare -A DUTY_MAP=(
  [unknown]=0
  [proposer]=1
  [attester]=2
  [signature]=3
  [exit]=4
  [builder_proposer]=5
  [builder_registration]=6
  [randao]=7
  [prepare_aggregator]=8
  [aggregator]=9
  [sync_message]=10
  [prepare_sync_contribution]=11
  [sync_contribution]=12
  [info_sync]=13
)

DUTY_VALUE="${DUTY_MAP[$DUTY_TYPE]:-}"
if [ -z "$DUTY_VALUE" ]; then
  echo "Error: unknown duty type '$DUTY_TYPE'" >&2
  echo "Valid types: ${!DUTY_MAP[*]}" >&2
  exit 1
fi

# Network genesis timestamps
declare -A GENESIS_TIME=(
  [mainnet]=1606824023
  [hoodi]=1742212800
  [sepolia]=1655733600
)

SLOTS_PER_EPOCH=32
SECONDS_PER_SLOT=12

GENESIS="${GENESIS_TIME[$NETWORK]:-}"
if [ -z "$GENESIS" ]; then
  echo "Error: unknown genesis time for network '$NETWORK'" >&2
  exit 1
fi

# Calculate time window for the slot
# Start from 15 seconds before slot (to catch scheduling), end 20 seconds after + 8 minutes for tracker
SLOT_TIMESTAMP=$((GENESIS + SLOT * SECONDS_PER_SLOT))
START_NS=$(( (SLOT_TIMESTAMP - 15) * 1000000000 ))
END_NS=$(( (SLOT_TIMESTAMP + 500) * 1000000000 ))  # ~8 minutes for tracker inclusion checks

# Discover Loki URL
DATASOURCES=$("$SCRIPT_DIR/grafana-datasources.sh")
LOKI_URL=$(echo "$DATASOURCES" | grep '^LOKI_URL=' | cut -d= -f2-)

if [ -z "$LOKI_URL" ]; then
  echo "Error: could not discover Loki URL" >&2
  exit 1
fi

AUTH="Authorization: Bearer $OBOL_GRAFANA_API_TOKEN"

# Fetch cluster config to get peer info
CLUSTER_OUTPUT=$("$SCRIPT_DIR/cluster-config.sh" "$CLUSTER_NAME" "$NETWORK" 2>/dev/null) || {
  echo "Error: failed to fetch cluster config" >&2
  exit 1
}

NODES=$(echo "$CLUSTER_OUTPUT" | grep '^Nodes:' | sed -E 's/^Nodes:[[:space:]]*([0-9]+).*/\1/')

# Extract peers
declare -a PEERS
while IFS= read -r line; do
  if [[ "$line" =~ ^INDEX ]] || [ -z "$line" ]; then
    continue
  fi
  PEER=$(echo "$line" | awk '{print $2}')
  PEERS+=("$PEER")
done < <(echo "$CLUSTER_OUTPUT" | sed -n '/=== Peers/,$ p' | tail -n +2)

# Calculate leaders for rounds 1, 2, 3
calc_leader() {
  local round=$1
  echo $(( (SLOT + DUTY_VALUE + round) % NODES ))
}

LEADER_R1=$(calc_leader 1)
LEADER_R2=$(calc_leader 2)
LEADER_R3=$(calc_leader 3)

LEADER_PEER_R1="${PEERS[$LEADER_R1]:-unknown}"
LEADER_PEER_R2="${PEERS[$LEADER_R2]:-unknown}"
LEADER_PEER_R3="${PEERS[$LEADER_R3]:-unknown}"

# Calculate epoch and slot time
EPOCH=$((SLOT / SLOTS_PER_EPOCH))
SLOT_IN_EPOCH=$((SLOT % SLOTS_PER_EPOCH))
SLOT_TIME=$(TZ=UTC date -r "$SLOT_TIMESTAMP" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || TZ=UTC date -d "@$SLOT_TIMESTAMP" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "")

echo "=== Duty Info ==="
echo "Slot:       ${SLOT}"
echo "Epoch:      ${EPOCH} (slot ${SLOT_IN_EPOCH} of ${SLOTS_PER_EPOCH})"
echo "Time:       ${SLOT_TIME}"
echo "Network:    ${NETWORK}"
echo "Duty:       ${DUTY_TYPE}"
echo ""
echo "=== Expected Consensus Leaders ==="
echo "Round 1:    ${LEADER_PEER_R1} (index ${LEADER_R1})"
echo "Round 2:    ${LEADER_PEER_R2} (index ${LEADER_R2})"
echo "Round 3:    ${LEADER_PEER_R3} (index ${LEADER_R3})"
echo ""

# Query Loki for all logs related to this slot and duty
# Match various log formats for the duty
DUTY_PATTERN="${SLOT}/${DUTY_TYPE}"
LOGQL="{cluster_name=\"${CLUSTER_NAME}\",cluster_network=\"${NETWORK}\"} |~ \`${DUTY_PATTERN}|duty=${DUTY_TYPE}.*slot=${SLOT}|slot.*${SLOT}.*${DUTY_TYPE}\`"

loki_query() {
  local query="$1"
  curl -sf -G \
    -H "$AUTH" \
    --data-urlencode "query=${query}" \
    --data-urlencode "start=${START_NS}" \
    --data-urlencode "end=${END_NS}" \
    --data-urlencode "limit=1000" \
    "${LOKI_URL}query_range"
}

echo "=== Fetching Logs ==="
LOGS_RAW=$(loki_query "$LOGQL")

# Save raw Loki JSON to temp file for Python processing
LOKI_TMPFILE=$(mktemp)
trap 'rm -f "$LOKI_TMPFILE"' EXIT
echo "$LOGS_RAW" > "$LOKI_TMPFILE"

# Process logs with Python (handles nanosecond timestamps correctly)
python3 - "$LOKI_TMPFILE" "$SLOT" "$SLOT_TIMESTAMP" "$DUTY_TYPE" \
  "$LEADER_PEER_R1" "$LEADER_R1" \
  "$LEADER_PEER_R2" "$LEADER_R2" \
  "$LEADER_PEER_R3" "$LEADER_R3" \
  "$SLOT_TIME" <<'PYTHON_SCRIPT'
import json
import re
import sys
from collections import defaultdict

loki_file = sys.argv[1]
slot = int(sys.argv[2])
slot_timestamp = int(sys.argv[3])
duty_type = sys.argv[4]
leader_peer_r1, leader_idx_r1 = sys.argv[5], sys.argv[6]
leader_peer_r2, leader_idx_r2 = sys.argv[7], sys.argv[8]
leader_peer_r3, leader_idx_r3 = sys.argv[9], sys.argv[10]
slot_time = sys.argv[11]

slot_timestamp_ns = slot_timestamp * 1_000_000_000

with open(loki_file) as f:
    data = json.load(f)

results = data.get("data", {}).get("result", [])
if not results:
    print()
    print(f"ERROR: No logs found for {slot}/{duty_type}")
    print("This could mean:")
    print(f"  - The cluster did not have this duty in slot {slot}")
    print("  - Logs have been rotated/deleted")
    print("  - The cluster name or network is incorrect")
    sys.exit(1)

# Parse all log entries
entries = []
for stream in results:
    peer = stream.get("stream", {}).get("cluster_peer", "unknown")
    for ts_str, line in stream.get("values", []):
        entries.append((int(ts_str), peer, line))

entries.sort(key=lambda x: x[0])
print(f"Found {len(entries)} log entries")
print()


def extract_logfmt(line, field):
    """Extract a field value from a logfmt-formatted line."""
    # Try quoted value first
    m = re.search(rf'{field}="([^"]*)"', line)
    if m:
        return m.group(1)
    # Try unquoted value
    m = re.search(rf'{field}=(\S+)', line)
    if m:
        return m.group(1)
    return ""


def calc_offset(ts_ns):
    """Calculate offset from slot start in seconds."""
    offset_ms = (ts_ns - slot_timestamp_ns) / 1_000_000
    offset_s = offset_ms / 1000
    return f"{offset_s:+.3f}s"


def fmt(offset, tag, msg, indent_continuation=None):
    """Format a timeline row."""
    line = f"  {offset}  [{tag}]{' ' * max(1, 10 - len(tag))} {msg}"
    if indent_continuation:
        line += f"\n{'':24s} {indent_continuation}"
    return line


# --- Collect events ---
# We'll build a list of (ts_ns, sort_priority, formatted_line) tuples
# sort_priority breaks ties: lower = earlier in output for same timestamp
timeline = []

# Track state for summary
consensus_started = False
consensus_decided = False
decided_round = ""
decided_leader = ""
decided_index = ""
round_timeout_reasons = {}
seen_first = set()  # for first-only events

# Per-peer tracking for summary
bn_call_rtts = {}       # peer -> rtt string
broadcast_delays = {}   # peer -> delay string
block_type = None       # "blinded" or "unblinded"
broadcast_success = False
broadcast_timeout = False
tracker_all = False
tracker_partial = False
tracker_absent = ""
tracker_missed = False
tracker_broadcast_delay = ""
error_peers = defaultdict(list)  # peer -> [error messages]

for ts_ns, peer, line in entries:
    msg = extract_logfmt(line, "msg")
    level = extract_logfmt(line, "level")
    if not msg:
        continue

    offset = calc_offset(ts_ns)

    # --- SCHEDULER ---
    if msg == "Slot ticked":
        if "slot_ticked" not in seen_first:
            seen_first.add("slot_ticked")
            timeline.append((ts_ns, 0, fmt(offset, "SCHED", f"Slot {slot} started")))

    elif msg in ("Resolved proposer duty", "Resolved attester duty"):
        pubkey = extract_logfmt(line, "pubkey")
        vidx = extract_logfmt(line, "vidx")
        key = f"resolved:{pubkey}"
        if key not in seen_first:
            seen_first.add(key)
            timeline.append((ts_ns, 1, fmt(offset, "SCHED",
                f"Resolved {duty_type} duty (vidx={vidx}, pubkey={pubkey})")))

    # --- FETCHER (per-peer) ---
    elif msg == "Calling beacon node endpoint...":
        endpoint = extract_logfmt(line, "endpoint")
        timeline.append((ts_ns, 10, fmt(offset, "FETCHER",
            f"BN call start: {endpoint} [{peer}]")))

    elif msg == "Beacon node call finished":
        endpoint = extract_logfmt(line, "endpoint")
        rtt = extract_logfmt(line, "rtt")
        rtt_part = f" (RTT={rtt})" if rtt else ""
        timeline.append((ts_ns, 11, fmt(offset, "FETCHER",
            f"BN call done:  {endpoint} [{peer}]{rtt_part}")))
        if rtt:
            bn_call_rtts[peer] = rtt

    elif msg == "Beacon node call took longer than expected":
        endpoint = extract_logfmt(line, "endpoint")
        rtt = extract_logfmt(line, "rtt")
        timeline.append((ts_ns, 12, fmt(offset, "FETCHER",
            f"SLOW BN call:  {endpoint} [{peer}] (RTT={rtt})")))
        if rtt:
            bn_call_rtts[peer] = rtt

    # --- CONSENSUS ---
    elif msg == "QBFT consensus instance starting":
        if not consensus_started:
            consensus_started = True
            timeline.append((ts_ns, 20, fmt(offset, "QBFT", "Consensus started")))

    elif msg == "QBFT round changed":
        old_round = extract_logfmt(line, "round")
        new_round = extract_logfmt(line, "new_round")
        reason = extract_logfmt(line, "timeout_reason")
        if old_round not in round_timeout_reasons:
            round_timeout_reasons[old_round] = reason
            timeline.append((ts_ns, 21, fmt(offset, "QBFT",
                f"Round {old_round} TIMEOUT -> Round {new_round}",
                f"Reason: {reason}")))

    elif msg == "QBFT consensus decided":
        if not consensus_decided:
            consensus_decided = True
            decided_round = extract_logfmt(line, "round")
            decided_leader = extract_logfmt(line, "leader_name")
            decided_index = extract_logfmt(line, "leader_index")
            timeline.append((ts_ns, 22, fmt(offset, "QBFT",
                f"Consensus DECIDED in round {decided_round}",
                f"Leader: {decided_leader} (index {decided_index})")))

    # --- VALIDATOR API (per-peer) ---
    elif msg == "Beacon block proposal received from validator client":
        block_version = extract_logfmt(line, "block_version")
        block_type = "unblinded"
        timeline.append((ts_ns, 30, fmt(offset, "VAPI",
            f"Block proposal received [{peer}] (version={block_version})")))

    elif msg == "Blinded beacon block received from validator client":
        block_version = extract_logfmt(line, "block_version")
        block_type = "blinded"
        timeline.append((ts_ns, 30, fmt(offset, "VAPI",
            f"Blinded block received [{peer}] (version={block_version})")))

    # --- SIG AGGREGATION (per-peer) ---
    elif msg == "Successfully aggregated partial signatures to reach threshold":
        vapi_endpoint = extract_logfmt(line, "vapi_endpoint")
        ep_part = f" ({vapi_endpoint})" if vapi_endpoint else ""
        timeline.append((ts_ns, 40, fmt(offset, "SIGAGG",
            f"Threshold reached [{peer}]{ep_part}")))

    # --- BROADCAST (per-peer) ---
    elif msg in ("Successfully submitted proposal to beacon node",
                 "Successfully submitted block proposal to beacon node",
                 "Successfully submitted v2 attestations to beacon node"):
        delay = extract_logfmt(line, "delay")
        broadcast_success = True
        delay_part = f" (delay={delay})" if delay else ""
        timeline.append((ts_ns, 50, fmt(offset, "BCAST",
            f"Broadcast SUCCESS [{peer}]{delay_part}")))
        if delay:
            broadcast_delays[peer] = delay

    elif msg == "Timeout calling bcast/broadcast, duty expired":
        vapi_endpoint = extract_logfmt(line, "vapi_endpoint")
        broadcast_timeout = True
        timeline.append((ts_ns, 51, fmt(offset, "BCAST",
            f"TIMEOUT: duty expired [{peer}] ({vapi_endpoint})")))

    # --- SSE EVENTS (per-peer for "too late", first for normal) ---
    elif msg == "Beacon node received block_gossip event too late":
        gossip_delay = extract_logfmt(line, "gossip_delay") or extract_logfmt(line, "delay")
        delay_part = f" (delay={gossip_delay})" if gossip_delay else ""
        timeline.append((ts_ns, 55, fmt(offset, "SSE",
            f"block_gossip TOO LATE [{peer}]{delay_part}")))

    elif msg == "Beacon node received block event too late":
        block_delay = extract_logfmt(line, "block_delay") or extract_logfmt(line, "delay")
        delay_part = f" (delay={block_delay})" if block_delay else ""
        timeline.append((ts_ns, 55, fmt(offset, "SSE",
            f"block event TOO LATE [{peer}]{delay_part}")))

    elif msg in ("SSE block gossip event", "SSE head event", "SSE block event"):
        key = f"sse:{msg}"
        if key not in seen_first:
            seen_first.add(key)
            timeline.append((ts_ns, 56, fmt(offset, "SSE", msg)))

    # --- TRACKER (first only) ---
    elif msg == "All peers participated in duty":
        if "tracker_all" not in seen_first:
            seen_first.add("tracker_all")
            tracker_all = True
            timeline.append((ts_ns, 60, fmt(offset, "TRACKER",
                "All peers participated")))

    elif msg == "Not all peers participated in duty":
        if "tracker_partial" not in seen_first:
            seen_first.add("tracker_partial")
            tracker_partial = True
            tracker_absent = extract_logfmt(line, "absent")
            timeline.append((ts_ns, 60, fmt(offset, "TRACKER",
                "Not all peers participated",
                f"Absent: {tracker_absent}")))

    elif msg == "Broadcasted block never included on-chain":
        if "tracker_missed" not in seen_first:
            seen_first.add("tracker_missed")
            tracker_missed = True
            pubkey = extract_logfmt(line, "pubkey")
            tracker_broadcast_delay = extract_logfmt(line, "broadcast_delay")
            timeline.append((ts_ns, 61, fmt(offset, "TRACKER",
                "BLOCK MISSED: never included on-chain",
                f"Pubkey: {pubkey}, Broadcast delay: {tracker_broadcast_delay}")))

    elif msg == "Broadcasted blinded block never included on-chain":
        if "tracker_missed_blinded" not in seen_first:
            seen_first.add("tracker_missed_blinded")
            tracker_missed = True
            pubkey = extract_logfmt(line, "pubkey")
            tracker_broadcast_delay = extract_logfmt(line, "broadcast_delay")
            timeline.append((ts_ns, 61, fmt(offset, "TRACKER",
                "BLINDED BLOCK MISSED: never included on-chain",
                f"Pubkey: {pubkey}, Broadcast delay: {tracker_broadcast_delay}")))

    # --- ERRORS (per-peer) ---
    elif level == "error" and ("consensus timeout" in msg.lower() or "permanent failure" in msg.lower()):
        error_peers[peer].append(msg)
        timeline.append((ts_ns, 70, fmt(offset, "ERROR",
            f"{msg} [{peer}]")))

# Sort and print timeline
timeline.sort(key=lambda x: (x[0], x[1]))

print("=== Event Timeline ===")
print(f"(Offset relative to slot start time: {slot_time})")
print()

for _, _, line in timeline:
    print(line)

print()
print("=== Summary ===")

# Consensus summary
if consensus_started:
    if consensus_decided:
        num_timeouts = len(round_timeout_reasons)
        if num_timeouts == 0:
            print("Consensus:     Completed in round 1 (optimal)")
        else:
            print(f"Consensus:     Completed in round {decided_round} after {num_timeouts} timeout(s)")
            print(f"               Leader: {decided_leader} (index {decided_index})")
            if "1" in round_timeout_reasons:
                print(f"               Round 1 leader {leader_peer_r1} failed")
    else:
        print("Consensus:     Did NOT complete")
else:
    print("Consensus:     Not started (logs may be incomplete)")

# Block type
if block_type:
    print(f"Block type:    {block_type}")

# Broadcast summary
if broadcast_timeout:
    print("Broadcast:     TIMEOUT - duty expired before broadcast")
elif broadcast_success:
    if broadcast_delays:
        delays_str = ", ".join(f"{p}={d}" for p, d in sorted(broadcast_delays.items()))
        # Parse delay values for min-max
        delay_vals = []
        for d in broadcast_delays.values():
            m = re.search(r'[\d.]+', d)
            if m:
                delay_vals.append(float(m.group()))
        if len(delay_vals) >= 2:
            print(f"Broadcast:     Successfully submitted (delay range: {min(delay_vals):.1f}s-{max(delay_vals):.1f}s)")
        else:
            print(f"Broadcast:     Successfully submitted ({delays_str})")
    else:
        print("Broadcast:     Successfully submitted to beacon node")
else:
    print("Broadcast:     No broadcast event found in logs")

# BN call RTT summary
if bn_call_rtts:
    rtt_vals = []
    for r in bn_call_rtts.values():
        m = re.search(r'[\d.]+', r)
        if m:
            rtt_vals.append(float(m.group()))
    if rtt_vals:
        if len(rtt_vals) >= 2:
            print(f"BN call RTT:   {min(rtt_vals):.1f}s-{max(rtt_vals):.1f}s across {len(rtt_vals)} peers")
        else:
            rtts_str = ", ".join(f"{p}={r}" for p, r in sorted(bn_call_rtts.items()))
            print(f"BN call RTT:   {rtts_str}")

# Inclusion summary (for proposer)
if duty_type == "proposer":
    if tracker_missed:
        delay_part = f" (broadcast_delay={tracker_broadcast_delay})" if tracker_broadcast_delay else ""
        print(f"Inclusion:     MISSED - block never included on-chain{delay_part}")
    elif tracker_all:
        print("Inclusion:     Block included on-chain")
    else:
        print("Inclusion:     Unknown (tracker event not found)")

# Participation summary
if tracker_partial:
    print(f"Participation: Not all peers participated (absent: {tracker_absent})")
elif tracker_all:
    print("Participation: All peers participated")

# Error summary
if error_peers:
    print("Errors:")
    for p, msgs in sorted(error_peers.items()):
        for m in msgs:
            print(f"  - [{p}] {m}")

print()
PYTHON_SCRIPT
