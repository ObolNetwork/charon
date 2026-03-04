#!/usr/bin/env bash
# Fetches Prometheus and Loki datasource proxy URLs from Grafana.
# Requires OBOL_GRAFANA_API_TOKEN environment variable.
# Output: two lines in KEY=URL format, e.g.:
#   PROMETHEUS_URL=https://grafana.monitoring.gcp.obol.tech/api/datasources/proxy/<id>/api/v1/
#   LOKI_URL=https://grafana.monitoring.gcp.obol.tech/api/datasources/proxy/<id>/loki/api/v1/

set -euo pipefail

GRAFANA_BASE="https://grafana.monitoring.gcp.obol.tech"

if [ -z "${OBOL_GRAFANA_API_TOKEN:-}" ]; then
  echo "Error: OBOL_GRAFANA_API_TOKEN is not set" >&2
  exit 1
fi

response=$(curl -sf -H "Authorization: Bearer $OBOL_GRAFANA_API_TOKEN" "$GRAFANA_BASE/api/datasources")

# Extract the main Prometheus (name="prometheus") and Loki datasource numeric IDs.
# Grafana datasource proxy requires numeric ID, not UID.
prom_id=$(echo "$response" | jq -r '.[] | select(.type=="prometheus" and .name=="prometheus") | .id')
loki_id=$(echo "$response" | jq -r '.[] | select(.type=="loki" and .name=="Loki") | .id')

if [ -z "$prom_id" ]; then
  echo "Error: Prometheus datasource not found" >&2
  exit 1
fi
if [ -z "$loki_id" ]; then
  echo "Error: Loki datasource not found" >&2
  exit 1
fi

echo "PROMETHEUS_URL=${GRAFANA_BASE}/api/datasources/proxy/${prom_id}/api/v1/"
echo "LOKI_URL=${GRAFANA_BASE}/api/datasources/proxy/${loki_id}/loki/api/v1/"
