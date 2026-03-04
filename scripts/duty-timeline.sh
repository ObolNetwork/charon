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

if [ -z "$LOGS_RAW" ] || [ "$(echo "$LOGS_RAW" | jq -r '.data.result | length')" = "0" ]; then
  echo ""
  echo "ERROR: No logs found for ${DUTY_PATTERN}"
  echo "This could mean:"
  echo "  - The cluster did not have this duty in slot ${SLOT}"
  echo "  - Logs have been rotated/deleted"
  echo "  - The cluster name or network is incorrect"
  exit 1
fi

LOG_COUNT=$(echo "$LOGS_RAW" | jq '[.data.result[].values[]] | length')
echo "Found ${LOG_COUNT} log entries"
echo ""

# Helper function to extract value from logfmt line
extract_logfmt() {
  local line="$1"
  local field="$2"
  echo "$line" | grep -oE "${field}=\"[^\"]*\"|${field}=[^ ]*" | head -1 | sed -E "s/${field}=\"?([^\"]*)\"?/\1/" || true
}

# Calculate offset from slot start using Loki nanosecond timestamp
SLOT_TIMESTAMP_NS=$((SLOT_TIMESTAMP * 1000000000))
calc_offset() {
  local loki_ts_ns="$1"
  local offset_ms=$(( (loki_ts_ns - SLOT_TIMESTAMP_NS) / 1000000 ))
  local offset_s=$(echo "scale=3; $offset_ms / 1000" | bc)
  printf "%+.3fs" "$offset_s"
}

# Parse logs and extract key events
# Each stream has labels and values; values are [timestamp, log_line]
PARSED_LOGS=$(echo "$LOGS_RAW" | jq -r '
  .data.result[] |
  .stream as $labels |
  .values[] |
  {
    ts: .[0],
    peer: $labels.cluster_peer,
    line: .[1]
  }
' | jq -s 'sort_by(.ts)')

echo "=== Event Timeline ==="
echo "(Offset relative to slot start time: ${SLOT_TIME})"
echo ""

# Track key events
declare -A SEEN_EVENTS
CONSENSUS_STARTED=false
CONSENSUS_DECIDED=false
DECIDED_ROUND=""
DECIDED_LEADER=""
declare -A ROUND_TIMEOUT_REASONS

# Process each log line and extract key events
while IFS= read -r entry; do
  [ -z "$entry" ] && continue

  PEER=$(echo "$entry" | jq -r '.peer')
  LINE=$(echo "$entry" | jq -r '.line')
  LOKI_TS=$(echo "$entry" | jq -r '.ts')

  # Extract fields from log line
  MSG=$(extract_logfmt "$LINE" "msg")
  LEVEL=$(extract_logfmt "$LINE" "level")
  CALLER=$(extract_logfmt "$LINE" "caller")

  # Determine component from caller (e.g., qbft/qbft.go -> qbft)
  COMPONENT=$(echo "$CALLER" | cut -d/ -f1)

  if [ -z "$MSG" ]; then
    continue
  fi

  # Calculate offset from slot start using Loki nanosecond timestamp
  OFFSET=$(calc_offset "$LOKI_TS" 2>/dev/null || echo "+?.???s")

  # Create unique event key to avoid duplicate output
  EVENT_KEY="${MSG}:${PEER}"

  # Process different event types
  case "$MSG" in
    "Slot ticked")
      if [ -z "${SEEN_EVENTS[slot_ticked]:-}" ]; then
        echo "  ${OFFSET}  [SCHED]    Slot ${SLOT} started"
        SEEN_EVENTS[slot_ticked]=1
      fi
      ;;

    "Resolved proposer duty"|"Resolved attester duty")
      PUBKEY=$(extract_logfmt "$LINE" "pubkey")
      VIDX=$(extract_logfmt "$LINE" "vidx")
      EVENT_KEY="resolved:${PUBKEY}"
      if [ -z "${SEEN_EVENTS[$EVENT_KEY]:-}" ]; then
        echo "  ${OFFSET}  [SCHED]    Resolved ${DUTY_TYPE} duty (vidx=${VIDX}, pubkey=${PUBKEY})"
        SEEN_EVENTS[$EVENT_KEY]=1
      fi
      ;;

    "Calling beacon node endpoint...")
      ENDPOINT=$(extract_logfmt "$LINE" "endpoint")
      EVENT_KEY="fetch_start:${ENDPOINT}"
      if [ -z "${SEEN_EVENTS[$EVENT_KEY]:-}" ]; then
        echo "  ${OFFSET}  [FETCHER]  Calling beacon node: ${ENDPOINT}"
        SEEN_EVENTS[$EVENT_KEY]=1
      fi
      ;;

    "Beacon node call finished")
      ENDPOINT=$(extract_logfmt "$LINE" "endpoint")
      EVENT_KEY="fetch_done:${ENDPOINT}"
      if [ -z "${SEEN_EVENTS[$EVENT_KEY]:-}" ]; then
        echo "  ${OFFSET}  [FETCHER]  Beacon node call finished: ${ENDPOINT}"
        SEEN_EVENTS[$EVENT_KEY]=1
      fi
      ;;

    "Beacon node call took longer than expected")
      ENDPOINT=$(extract_logfmt "$LINE" "endpoint")
      RTT=$(extract_logfmt "$LINE" "rtt")
      EVENT_KEY="fetch_slow:${ENDPOINT}"
      if [ -z "${SEEN_EVENTS[$EVENT_KEY]:-}" ]; then
        echo "  ${OFFSET}  [FETCHER]  ⚠️  SLOW beacon node call: ${ENDPOINT} (RTT=${RTT})"
        SEEN_EVENTS[$EVENT_KEY]=1
      fi
      ;;

    "QBFT consensus instance starting")
      if [ "$CONSENSUS_STARTED" = false ]; then
        CONSENSUS_STARTED=true
        echo "  ${OFFSET}  [QBFT]     Consensus started"
      fi
      ;;

    "QBFT round changed")
      OLD_ROUND=$(extract_logfmt "$LINE" "round")
      NEW_ROUND=$(extract_logfmt "$LINE" "new_round")
      REASON=$(extract_logfmt "$LINE" "timeout_reason")
      if [ -z "${ROUND_TIMEOUT_REASONS[$OLD_ROUND]:-}" ]; then
        echo "  ${OFFSET}  [QBFT]     ⚠️  Round ${OLD_ROUND} TIMEOUT -> Round ${NEW_ROUND}"
        echo "                        Reason: ${REASON}"
        ROUND_TIMEOUT_REASONS[$OLD_ROUND]="$REASON"
      fi
      ;;

    "QBFT consensus decided")
      if [ "$CONSENSUS_DECIDED" = false ]; then
        CONSENSUS_DECIDED=true
        DECIDED_ROUND=$(extract_logfmt "$LINE" "round")
        DECIDED_LEADER=$(extract_logfmt "$LINE" "leader_name")
        DECIDED_INDEX=$(extract_logfmt "$LINE" "leader_index")
        echo "  ${OFFSET}  [QBFT]     ✓ Consensus DECIDED in round ${DECIDED_ROUND}"
        echo "                        Leader: ${DECIDED_LEADER} (index ${DECIDED_INDEX})"
      fi
      ;;

    "Successfully aggregated partial signatures to reach threshold")
      VAPI_ENDPOINT=$(extract_logfmt "$LINE" "vapi_endpoint")
      if [ -n "$VAPI_ENDPOINT" ]; then
        EVENT_KEY="sigagg:${VAPI_ENDPOINT}"
      else
        EVENT_KEY="sigagg:${DUTY_TYPE}"
      fi
      if [ -z "${SEEN_EVENTS[$EVENT_KEY]:-}" ]; then
        if [ -n "$VAPI_ENDPOINT" ]; then
          echo "  ${OFFSET}  [SIGAGG]   ✓ Threshold signatures aggregated (${VAPI_ENDPOINT})"
        else
          echo "  ${OFFSET}  [SIGAGG]   ✓ Threshold signatures aggregated"
        fi
        SEEN_EVENTS[$EVENT_KEY]=1
      fi
      ;;

    "Beacon block proposal received from validator client")
      BLOCK_VERSION=$(extract_logfmt "$LINE" "block_version")
      EVENT_KEY="vapi_proposal"
      if [ -z "${SEEN_EVENTS[$EVENT_KEY]:-}" ]; then
        echo "  ${OFFSET}  [VAPI]     Block proposal received (version=${BLOCK_VERSION})"
        SEEN_EVENTS[$EVENT_KEY]=1
      fi
      ;;

    "Successfully submitted v2 attestations to beacon node"|"Successfully submitted proposal to beacon node")
      DELAY=$(extract_logfmt "$LINE" "delay")
      EVENT_KEY="bcast_success:${MSG}"
      if [ -z "${SEEN_EVENTS[$EVENT_KEY]:-}" ]; then
        if [ -n "$DELAY" ]; then
          echo "  ${OFFSET}  [BCAST]    ✓ Broadcast SUCCESS (delay=${DELAY})"
        else
          echo "  ${OFFSET}  [BCAST]    ✓ Broadcast SUCCESS"
        fi
        SEEN_EVENTS[$EVENT_KEY]=1
      fi
      ;;

    "Timeout calling bcast/broadcast, duty expired")
      VAPI_ENDPOINT=$(extract_logfmt "$LINE" "vapi_endpoint")
      EVENT_KEY="bcast_timeout:${VAPI_ENDPOINT}"
      if [ -z "${SEEN_EVENTS[$EVENT_KEY]:-}" ]; then
        echo "  ${OFFSET}  [BCAST]    ❌ TIMEOUT: duty expired (${VAPI_ENDPOINT})"
        SEEN_EVENTS[$EVENT_KEY]=1
      fi
      ;;

    "All peers participated in duty")
      EVENT_KEY="tracker_all"
      if [ -z "${SEEN_EVENTS[$EVENT_KEY]:-}" ]; then
        echo "  ${OFFSET}  [TRACKER]  ✓ All peers participated"
        SEEN_EVENTS[$EVENT_KEY]=1
      fi
      ;;

    "Not all peers participated in duty")
      ABSENT=$(extract_logfmt "$LINE" "absent")
      EVENT_KEY="tracker_partial"
      if [ -z "${SEEN_EVENTS[$EVENT_KEY]:-}" ]; then
        echo "  ${OFFSET}  [TRACKER]  ⚠️  Not all peers participated"
        echo "                        Absent: ${ABSENT}"
        SEEN_EVENTS[$EVENT_KEY]=1
      fi
      ;;

    "Broadcasted block never included on-chain")
      PUBKEY=$(extract_logfmt "$LINE" "pubkey")
      BLOCK_SLOT=$(extract_logfmt "$LINE" "block_slot")
      BROADCAST_DELAY=$(extract_logfmt "$LINE" "broadcast_delay")
      EVENT_KEY="tracker_missed"
      if [ -z "${SEEN_EVENTS[$EVENT_KEY]:-}" ]; then
        echo "  ${OFFSET}  [TRACKER]  ❌ BLOCK MISSED: never included on-chain"
        echo "                        Pubkey: ${PUBKEY}, Broadcast delay: ${BROADCAST_DELAY}"
        SEEN_EVENTS[$EVENT_KEY]=1
      fi
      ;;

    *"consensus timeout"*|*"duty expired"*)
      if [[ "$LEVEL" == "error" ]]; then
        EVENT_KEY="error:${MSG:0:50}"
        if [ -z "${SEEN_EVENTS[$EVENT_KEY]:-}" ]; then
          echo "  ${OFFSET}  [ERROR]    ❌ ${MSG}"
          SEEN_EVENTS[$EVENT_KEY]=1
        fi
      fi
      ;;
  esac
done < <(echo "$PARSED_LOGS" | jq -c '.[]')

echo ""
echo "=== Summary ==="

# Consensus summary
if [ "$CONSENSUS_STARTED" = true ]; then
  if [ "$CONSENSUS_DECIDED" = true ]; then
    NUM_TIMEOUTS=${#ROUND_TIMEOUT_REASONS[@]}
    if [ "$NUM_TIMEOUTS" -eq 0 ]; then
      echo "Consensus:  ✓ Completed in round 1 (optimal)"
    else
      echo "Consensus:  ✓ Completed in round ${DECIDED_ROUND} after ${NUM_TIMEOUTS} timeout(s)"
      echo "            Leader: ${DECIDED_LEADER} (index ${DECIDED_INDEX})"
      if [ -n "${ROUND_TIMEOUT_REASONS[1]:-}" ]; then
        echo "            ⚠️  Round 1 leader ${LEADER_PEER_R1} failed"
      fi
    fi
  else
    echo "Consensus:  ❌ Did NOT complete"
  fi
else
  echo "Consensus:  ⚠️  Not started (logs may be incomplete)"
fi

# Broadcast summary
if [ -n "${SEEN_EVENTS[bcast_timeout:submit_proposal_v2]:-}" ] || [ -n "${SEEN_EVENTS[bcast_timeout:submit_attestation]:-}" ]; then
  echo "Broadcast:  ❌ TIMEOUT - duty expired before broadcast"
elif [ -n "${SEEN_EVENTS[bcast_success:Successfully submitted v2 attestations to beacon node]:-}" ] || \
     [ -n "${SEEN_EVENTS[bcast_success:Successfully submitted proposal to beacon node]:-}" ]; then
  echo "Broadcast:  ✓ Successfully submitted to beacon node"
else
  echo "Broadcast:  ⚠️  No broadcast event found in logs"
fi

# Inclusion summary (for proposer)
if [ "$DUTY_TYPE" = "proposer" ]; then
  if [ -n "${SEEN_EVENTS[tracker_missed]:-}" ]; then
    echo "Inclusion:  ❌ MISSED - block never included on-chain"
  elif [ -n "${SEEN_EVENTS[tracker_all]:-}" ]; then
    echo "Inclusion:  ✓ Block included on-chain"
  else
    echo "Inclusion:  ⚠️  Unknown (tracker event not found)"
  fi
fi

# Participation summary
if [ -n "${SEEN_EVENTS[tracker_partial]:-}" ]; then
  echo "Participation: ⚠️  Not all peers participated"
elif [ -n "${SEEN_EVENTS[tracker_all]:-}" ]; then
  echo "Participation: ✓ All peers participated"
fi

echo ""
