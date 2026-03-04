#!/usr/bin/env bash
# Calculates consensus leader sequence for a given slot number.
# Requires OBOL_GRAFANA_API_TOKEN environment variable (passed to cluster-config.sh).
# Usage: bash scripts/consensus-leader.sh <cluster_name> <slot> [network] [duty_type]
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
  echo "Usage: bash scripts/consensus-leader.sh <cluster_name> <slot> [network] [duty_type]" >&2
  exit 1
fi

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

# Network genesis timestamps and slots per epoch
declare -A GENESIS_TIME=(
  [mainnet]=1606824023
  [hoodi]=1742212800
  [sepolia]=1655733600
)

SLOTS_PER_EPOCH=32
SECONDS_PER_SLOT=12

# Get genesis time for the network
GENESIS="${GENESIS_TIME[$NETWORK]:-}"
if [ -z "$GENESIS" ]; then
  echo "Warning: unknown genesis time for network '$NETWORK', skipping time calculation" >&2
fi

# Fetch cluster config using cluster-config.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER_OUTPUT=$("$SCRIPT_DIR/cluster-config.sh" "$CLUSTER_NAME" "$NETWORK")

# Extract number of nodes from "Nodes: N (threshold: T)"
NODES=$(echo "$CLUSTER_OUTPUT" | grep '^Nodes:' | sed -E 's/^Nodes:[[:space:]]*([0-9]+).*/\1/')

if [ -z "$NODES" ] || [ "$NODES" -eq 0 ]; then
  echo "Error: could not determine number of nodes from cluster config" >&2
  exit 1
fi

# Extract peer info lines (INDEX PEER NICKNAME VERSION)
# Skip header line, capture peers in order
declare -a PEERS
while IFS= read -r line; do
  # Skip header and empty lines
  if [[ "$line" =~ ^INDEX ]] || [ -z "$line" ]; then
    continue
  fi
  # Extract peer name (second column)
  PEER=$(echo "$line" | awk '{print $2}')
  PEERS+=("$PEER")
done < <(echo "$CLUSTER_OUTPUT" | sed -n '/=== Peers/,$ p' | tail -n +2)

# If we couldn't parse peers, create placeholder names
if [ ${#PEERS[@]} -eq 0 ]; then
  for ((i=0; i<NODES; i++)); do
    PEERS+=("peer-$i")
  done
fi

# Calculate epoch and slot within epoch
EPOCH=$((SLOT / SLOTS_PER_EPOCH))
SLOT_IN_EPOCH=$((SLOT % SLOTS_PER_EPOCH))

# Calculate absolute time if genesis is known
SLOT_TIME=""
if [ -n "$GENESIS" ]; then
  SLOT_TIMESTAMP=$((GENESIS + SLOT * SECONDS_PER_SLOT))
  SLOT_TIME=$(TZ=UTC date -r "$SLOT_TIMESTAMP" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || TZ=UTC date -d "@$SLOT_TIMESTAMP" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "")
fi

# Calculate leader indices for rounds 1, 2, 3
# Formula: (slot + dutyType + round) % nodes
calc_leader() {
  local round=$1
  echo $(( (SLOT + DUTY_VALUE + round) % NODES ))
}

LEADER_R1=$(calc_leader 1)
LEADER_R2=$(calc_leader 2)
LEADER_R3=$(calc_leader 3)

# Output results
echo "=== Slot Info ==="
echo "Slot:       ${SLOT}"
echo "Epoch:      ${EPOCH} (slot ${SLOT_IN_EPOCH} of ${SLOTS_PER_EPOCH})"
if [ -n "$SLOT_TIME" ]; then
  echo "Time:       ${SLOT_TIME}"
fi
echo "Network:    ${NETWORK}"
echo "Duty:       ${DUTY_TYPE} (value: ${DUTY_VALUE})"
echo ""
echo "=== Consensus Leaders ==="
echo "Cluster:    ${CLUSTER_NAME} (${NODES} nodes)"
echo ""
printf "%-8s %-5s %-20s\n" "ROUND" "INDEX" "PEER"
printf "%-8s %-5s %-20s\n" "1" "$LEADER_R1" "${PEERS[$LEADER_R1]:-unknown}"
printf "%-8s %-5s %-20s\n" "2" "$LEADER_R2" "${PEERS[$LEADER_R2]:-unknown}"
printf "%-8s %-5s %-20s\n" "3" "$LEADER_R3" "${PEERS[$LEADER_R3]:-unknown}"
