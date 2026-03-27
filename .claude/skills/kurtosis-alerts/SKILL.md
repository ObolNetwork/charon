```skill
---
name: kurtosis-alerts
description: Fetch and display Charon Kurtosis alert history for a given time range (e.g. "last 30 minutes", "last 2 hours")
user-invokable: true
---

# Kurtosis Alert Report

Fetch alert history from Grafana for Charon clusters running in a Kurtosis network, and present a human-friendly report grouped by cluster.

## Arguments

The user provides:
- **time range** (required): A human-friendly duration such as `last 30 minutes`, `last 2 hours`, `last hour`, `last 90 minutes`. Absolute ranges like `from 2025-03-27T10:00:00Z to 2025-03-27T11:00:00Z` are also accepted.

If the time range is unclear or missing, ask the user to clarify. Suggest examples:
> Please specify a time range, for example: "last 30 minutes", "last 2 hours", or "from 2025-03-27T10:00:00Z to 2025-03-27T11:00:00Z".

## Execution

### 1. Parse the time range

Convert the user's input into ISO 8601 `--from` and `--to` arguments:
- For relative durations (e.g. "last 2 hours"), compute `--to` as the current UTC time and `--from` as the current UTC time minus the duration.
- Use the `date` command to compute timestamps:
  ```bash
  # macOS
  FROM=$(date -u -v-2H +"%Y-%m-%dT%H:%M:%SZ")
  TO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  ```
- For absolute ranges, use the values provided directly.

### 2. Run the script

```bash
python3 scripts/debug/kurtosis_alerts.py --from "$FROM" --to "$TO"
```

The script outputs a JSON array to stdout. Stderr may contain informational messages (rule counts, warnings).

### 3. Check for errors

- If the output contains `{"error": "OBOL_GRAFANA_API_TOKEN environment variable is not set"}`, inform the user:
  > The `OBOL_GRAFANA_API_TOKEN` environment variable is not set. Please export it before running this skill.

- If the script exits with a non-zero code or produces an HTTP error on stderr, report the error clearly.

- If the output is an empty array `[]`, report:
  > No alerts were found in the specified time range. All clusters were healthy, or no Kurtosis clusters were running during that period.

## Analysis and Output

Parse the JSON array and produce a formatted report.

### 1. Overview

```
=== Kurtosis Alert Report ===
Time range:  <FROM> to <TO>
Total alerts: <count>
Clusters:     <number of distinct cluster_name values>
```

### 2. Observed Clusters

List all distinct `labels.cluster_name` values from the entire JSON output (all states, including `Normal`). This confirms which clusters were being monitored during the time range:

```
=== Observed Clusters ===
- <cluster_name> (hash: <cluster_hash>)
- <cluster_name> (hash: <cluster_hash>)
```

### 3. Alerts by Cluster

Group alerts by `labels.cluster_name`. For each cluster, sort alerts chronologically by `timestamp`:

```
--- <cluster_name> (hash: <cluster_hash>) ---

  HH:MM:SS UTC  [previous_state -> state]  alert_name
  HH:MM:SS UTC  [previous_state -> state]  alert_name
```

Convert `timestamp` (epoch milliseconds) to `HH:MM:SS UTC` for readability.

### 4. Alerts Still Firing

List clusters where the last known state for any alert is `Alerting`:

```
=== Alerts Still Firing ===
- <cluster_name>: <alert_name> (since HH:MM:SS UTC)
```

If none:
```
=== Alerts Still Firing ===
None - all alerts resolved.
```

### 5. Summary

Provide a brief summary:
- Total alert transitions observed
- Which clusters were most affected (most transitions)
- Whether all alerts resolved or some remain firing
- Any patterns (e.g. same alert across multiple clusters simultaneously suggests a systemic issue)

## Example Usage

User: "Show me kurtosis alerts for the last hour"

1. Parse "last hour" into `--from` (1 hour ago UTC) and `--to` (now UTC)
2. Run the script
3. Parse JSON output
4. Present formatted report grouped by cluster

User: "kurtosis alerts from 2025-03-27T14:00:00Z to 2025-03-27T15:30:00Z"

1. Use the provided timestamps directly
2. Run the script
3. Present the report

## Dependencies

- `python3` (standard library only)
- `OBOL_GRAFANA_API_TOKEN` environment variable must be set
- Access to Grafana at grafana.monitoring.gcp.obol.tech
```
