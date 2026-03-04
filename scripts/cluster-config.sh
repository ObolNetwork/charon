#!/usr/bin/env bash
# Fetches cluster configuration metrics from Prometheus via Grafana proxy.
# Requires OBOL_GRAFANA_API_TOKEN environment variable.
# Usage: bash scripts/cluster-config.sh <cluster_name> [network]
#   cluster_name: e.g. "Lido x Obol: Ethereal Elf"
#   network: mainnet (default), hoodi, sepolia, etc.

set -euo pipefail

CLUSTER_NAME="${1:-}"
NETWORK="${2:-mainnet}"

if [ -z "$CLUSTER_NAME" ]; then
  echo "Error: cluster name is required" >&2
  echo "Usage: bash scripts/cluster-config.sh <cluster_name> [network]" >&2
  exit 1
fi

if [ -z "${OBOL_GRAFANA_API_TOKEN:-}" ]; then
  echo "Error: OBOL_GRAFANA_API_TOKEN is not set" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Discover Prometheus proxy URL
PROM_URL=$("$SCRIPT_DIR/grafana-datasources.sh" | grep '^PROMETHEUS_URL=' | cut -d= -f2-)

if [ -z "$PROM_URL" ]; then
  echo "Error: could not discover Prometheus URL" >&2
  exit 1
fi

AUTH="Authorization: Bearer $OBOL_GRAFANA_API_TOKEN"

prom_query() {
  local metric="$1"
  curl -sf -G \
    -H "$AUTH" \
    --data-urlencode "query=${metric}{cluster_name=\"${CLUSTER_NAME}\",cluster_network=\"${NETWORK}\"}" \
    "${PROM_URL}query"
}

query_metric() {
  local metric="$1"
  local result
  result=$(prom_query "$metric")

  if [ "$metric" = "app_version" ]; then
    echo "$result" | jq -r '[.data.result[].metric.version] | unique | sort | join(", ") | if . == "" then "NOT_FOUND" else . end'
  else
    echo "$result" | jq -r 'if .data.result | length == 0 then "NOT_FOUND" else .data.result[0].value[1] end'
  fi
}

# Query cluster-level metrics; reuse operators raw result to extract common labels.
operators_raw=$(prom_query "cluster_operators")
operators=$(echo "$operators_raw" | jq -r 'if .data.result | length == 0 then "NOT_FOUND" else .data.result[0].value[1] end')
cluster_hash=$(echo "$operators_raw" | jq -r '.data.result[0].metric.cluster_hash // "NOT_FOUND"')

version=$(query_metric "app_version")
threshold=$(query_metric "cluster_threshold")
active_validators=$(query_metric "core_scheduler_validators_active")
total_validators=$(query_metric "cluster_validators")

# Check if cluster was found
all_not_found=true
for val in "$version" "$operators" "$threshold" "$active_validators" "$total_validators"; do
  if [ -n "$val" ] && [ "$val" != "NOT_FOUND" ]; then
    all_not_found=false
    break
  fi
done

if $all_not_found; then
  echo "Error: no cluster found for name=\"${CLUSTER_NAME}\" network=\"${NETWORK}\"" >&2
  echo "Please double-check the cluster name and network." >&2
  exit 1
fi

# Query per-peer info metrics for the peer table.
# app_peerinfo_* metrics use 'peer' label (= cluster_peer value of the described peer).
# app_peer_name uses 'cluster_peer' as key and 'peer_name' as the human-readable name.
# Multiple nodes report peerinfo for all peers, so results are deduplicated by peer.
# app_feature_flags is reported by each node for itself, keyed by 'cluster_peer'.
idx_raw=$(prom_query "app_peerinfo_index")
nick_raw=$(prom_query "app_peerinfo_nickname")
ver_raw=$(prom_query "app_peerinfo_version")
flags_raw=$(prom_query "app_feature_flags")

echo "=== Cluster Info ==="
echo "Name:       ${CLUSTER_NAME}"
echo "Hash:       ${cluster_hash}"
echo "Version:    ${version}"
echo "Network:    ${NETWORK}"
echo "Nodes:      ${operators} (threshold: ${threshold})"
echo "Validators: ${active_validators} active / ${total_validators} total"
echo ""
echo "=== Peers Info ==="
jq -rn \
  --argjson idx   "$idx_raw" \
  --argjson nicks "$nick_raw" \
  --argjson vers  "$ver_raw" \
  --argjson flags "$flags_raw" \
  '
  ($nicks.data.result | map({(.metric.peer): (.metric.peer_nickname // "?")}) | add // {}) as $nick_map  |
  ($vers.data.result  | map({(.metric.peer): (.metric.version       // "?")}) | add // {}) as $ver_map   |
  ($flags.data.result | map({(.metric.cluster_peer): (.metric.feature_flags // "")}) | add // {}) as $flags_map |
  ["INDEX", "PEER", "NICKNAME", "VERSION", "FEATURE_FLAGS"],
  (
    $idx.data.result
    | map({peer: .metric.peer, index: (.value[1] | tonumber)})
    | unique_by(.peer)
    | sort_by(.index)
    | .[]
    | [(.index | tostring), .peer, ($nick_map[.peer] // "?"), ($ver_map[.peer] // "?"), ($flags_map[.peer] // "-")]
  )
  | @tsv
  ' | column -t -s $'\t'
