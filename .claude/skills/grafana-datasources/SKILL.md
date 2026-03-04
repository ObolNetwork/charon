---
name: grafana-datasources
description: Discover Prometheus and Loki datasource proxy URLs from Grafana
user-invokable: true
---

# Grafana Datasources

Run the following script to discover Prometheus and Loki datasource proxy URLs from Grafana. The script requires the `OBOL_GRAFANA_API_TOKEN` environment variable.

Execute this command:
```bash
bash scripts/grafana-datasources.sh
```

Present the two output URLs to the user:
- **Prometheus**: for querying metrics via the Prometheus HTTP API (e.g., `query`, `query_range`)
- **Loki**: for querying logs via the Loki HTTP API (e.g., `query`, `query_range`)

This is a non-interactive skill. Do not ask the user any questions — just run the script and display the results.
