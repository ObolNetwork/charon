#!/usr/bin/env python3
"""
Fetches alert history for Charon Kurtosis alerts from Grafana.
Requires OBOL_GRAFANA_API_TOKEN environment variable.
Usage: python kurtosis_alerts.py --from <start> --to <end>
  --from: Start time (ISO 8601 e.g. 2024-03-01T00:00:00Z, or epoch seconds)
  --to:   End time (ISO 8601 e.g. 2024-03-02T00:00:00Z, or epoch seconds)

Outputs a structured report to stdout.
Exit code 0 if no firing alerts, 1 if firing alerts detected.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

GRAFANA_BASE = "https://grafana.monitoring.gcp.obol.tech"
TARGET_FOLDER = "Charon Kurtosis Alerts"
DASHBOARD_PATH = "/d/d6qujIJVk/charon-overview-v3"


def get_auth_header() -> dict:
    """Return authorization header using OBOL_GRAFANA_API_TOKEN."""
    token = os.environ.get("OBOL_GRAFANA_API_TOKEN")
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def fetch_json(url: str, headers: dict, silent: bool = False) -> dict | None:
    """Fetch JSON from URL with headers. Returns None on error if silent."""
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if not silent:
            print(f"Error: HTTP {e.code} fetching {url}", file=sys.stdout)
        return None
    except urllib.error.URLError as e:
        if not silent:
            print(f"Error: {e.reason}", file=sys.stdout)
        return None
    except Exception as e:
        if not silent:
            print(f"Error: {e}", file=sys.stdout)
        return None


def parse_timestamp(value: str) -> int:
    """Parse a timestamp string into epoch milliseconds.

    Accepts epoch seconds (integer string) or ISO 8601 datetime.
    """
    if value.isdigit():
        return int(value) * 1000

    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        print(f"Error: cannot parse timestamp '{value}'", file=sys.stdout)
        sys.exit(1)


def ms_to_human(ms: int) -> str:
    """Convert epoch milliseconds to human-readable UTC string."""
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def fetch_kurtosis_folder_uid(headers: dict) -> str | None:
    """Find the folder UID for the Charon Kurtosis Alerts folder."""
    url = f"{GRAFANA_BASE}/api/folders"
    folders = fetch_json(url, headers)
    if not folders:
        return None
    for folder in folders:
        if folder.get("title") == TARGET_FOLDER:
            return folder.get("uid")
    return None


def fetch_alert_rules(headers: dict, folder_uid: str) -> list[dict]:
    """Fetch alert rules belonging to the given folder."""
    url = f"{GRAFANA_BASE}/api/v1/provisioning/alert-rules"
    rules = fetch_json(url, headers)
    if not rules:
        return []
    return [
        {"uid": r["uid"], "title": r["title"]}
        for r in rules
        if r.get("folderUID") == folder_uid
    ]


def fetch_annotations(headers: dict, from_ms: int, to_ms: int) -> list[dict]:
    """Fetch alert annotations for the given time range."""
    params = urllib.parse.urlencode({
        "type": "alert",
        "from": str(from_ms),
        "to": str(to_ms),
        "limit": "5000",
    })
    url = f"{GRAFANA_BASE}/api/annotations?{params}"
    result = fetch_json(url, headers)
    return result if isinstance(result, list) else []


def format_alert_entry(annotation: dict) -> dict:
    """Transform a Grafana annotation into a structured alert history entry."""
    ts = annotation.get("time", 0)
    ts_end = annotation.get("timeEnd", 0)

    # Extract labels from the data field (JSON) if available
    labels = {}
    data = annotation.get("data", {})
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except (json.JSONDecodeError, TypeError):
            data = {}
    if isinstance(data, dict):
        for key in ("cluster_network", "cluster_name", "cluster_hash", "peer_name"):
            if key in data:
                labels[key] = data[key]
        # Also check nested "values" or "labels" keys
        for nested_key in ("labels", "values"):
            nested = data.get(nested_key, {})
            if isinstance(nested, dict):
                for key in ("cluster_network", "cluster_name", "cluster_hash", "peer_name"):
                    if key in nested and key not in labels:
                        labels[key] = nested[key]

    # Extract labels from tags (Grafana uses "key:value" format)
    skip_labels = {"alertname", "grafana_folder"}
    tags = annotation.get("tags", [])
    if isinstance(tags, list):
        for tag in tags:
            if ":" in tag:
                k, v = tag.split(":", 1)
                if k not in skip_labels:
                    labels[k] = v

    return {
        "alert_name": annotation.get("alertName", ""),
        "state": annotation.get("newState", ""),
        "previous_state": annotation.get("prevState", ""),
        "timestamp": ts,
        "time_end": ts_end,
        "labels": labels,
    }


def build_grafana_link(cluster_name: str, cluster_hash: str, from_ms: int, to_ms: int) -> str:
    """Build a Grafana dashboard link for a specific cluster."""
    params = urllib.parse.urlencode({
        "orgId": "1",
        "refresh": "1m",
        "var-interval": "$__auto",
        "from": str(from_ms),
        "to": str(to_ms),
        "timezone": "browser",
        "var-cluster_network": "kurtosis",
        "var-cluster_name": cluster_name,
        "var-cluster_hash": cluster_hash,
        "var-job": "charon",
        "var-duty": "$__all",
    })
    return f"{GRAFANA_BASE}{DASHBOARD_PATH}?{params}"


def is_firing(entry: dict) -> bool:
    """Check if an alert entry represents a firing alert."""
    return entry["state"].lower() == "alerting"


def print_report(entries: list[dict], from_ms: int, to_ms: int, rules: list[dict]):
    """Print a structured human-readable report."""
    firing = [e for e in entries if is_firing(e)]

    # === Section A: Input Parameters ===
    print("=== Input Parameters ===")
    print(f"From: {ms_to_human(from_ms)}")
    print(f"To:   {ms_to_human(to_ms)}")
    print()

    # === Section B: Alerts ===
    rule_names = sorted(r["title"] for r in rules)
    print(f"=== Alerts ({len(rules)}) ===")
    for name in rule_names:
        print(f"  - {name}")
    print()

    # === Section C: Clusters Observed ===
    clusters = {}  # (cluster_name, cluster_hash) -> set
    for e in entries:
        name = e["labels"].get("cluster_name", "")
        h = e["labels"].get("cluster_hash", "")
        if name or h:
            clusters[(name, h)] = True

    print("=== Clusters Observed ===")
    if not clusters:
        print("  (none)")
    else:
        for i, (name, h) in enumerate(sorted(clusters.keys()), 1):
            display_name = name or "(unknown)"
            display_hash = h or "(unknown)"
            print(f"{i}. {display_name} (hash: {display_hash})")
            link = build_grafana_link(name, h, from_ms, to_ms)
            print(f"   {link}")
    print()

    # === Section C: Firing Alerts ===
    print("=== Firing Alerts ===")
    if not firing:
        print("  No firing alerts detected.")
        return

    # Group by alert name
    by_alert = defaultdict(list)
    for e in firing:
        by_alert[e["alert_name"]].append(e)

    # Sort alerts by occurrence count (desc)
    for alert_name, alert_entries in sorted(by_alert.items(), key=lambda x: -len(x[1])):
        print(f"--- {alert_name} ({len(alert_entries)} occurrences) ---")

        # Group by cluster within this alert
        by_cluster = defaultdict(int)
        for e in alert_entries:
            name = e["labels"].get("cluster_name", "(unknown)")
            h = e["labels"].get("cluster_hash", "(unknown)")
            by_cluster[(name, h)] += 1

        for (name, h), count in sorted(by_cluster.items(), key=lambda x: -x[1]):
            print(f"  {name} (hash: {h}): {count} occurrences")
        print()


def _has_folder_tag(annotation: dict, folder_title: str) -> bool:
    """Check if an annotation's tags include the expected grafana_folder."""
    tags = annotation.get("tags", [])
    if not isinstance(tags, list):
        return False
    return f"grafana_folder:{folder_title}" in tags


def main():
    parser = argparse.ArgumentParser(
        description="Fetch Grafana alert history for Charon Kurtosis alerts.",
    )
    parser.add_argument(
        "--from", dest="time_from", required=True,
        help="Start time (ISO 8601 or epoch seconds)",
    )
    parser.add_argument(
        "--to", dest="time_to", required=True,
        help="End time (ISO 8601 or epoch seconds)",
    )
    args = parser.parse_args()

    from_ms = parse_timestamp(args.time_from)
    to_ms = parse_timestamp(args.time_to)

    headers = get_auth_header()
    if not headers:
        print(json.dumps({"error": "OBOL_GRAFANA_API_TOKEN environment variable is not set"}))
        sys.exit(1)

    # Find the target folder
    folder_uid = fetch_kurtosis_folder_uid(headers)
    if not folder_uid:
        print(f"Warning: folder '{TARGET_FOLDER}' not found", file=sys.stdout)
        print("=== No data available ===")
        sys.exit(0)

    # Get alert rules in the folder
    rules = fetch_alert_rules(headers, folder_uid)
    if not rules:
        print(f"Warning: no alert rules found in '{TARGET_FOLDER}'", file=sys.stdout)
        print("=== No data available ===")
        sys.exit(0)

    # Fetch annotations and filter by rule titles
    rule_titles = {r["title"] for r in rules}

    annotations = fetch_annotations(headers, from_ms, to_ms)
    matching = [
        a for a in annotations
        if a.get("alertName") in rule_titles
        and _has_folder_tag(a, TARGET_FOLDER)
    ]

    # Format and sort by timestamp
    entries = [format_alert_entry(a) for a in matching]
    entries.sort(key=lambda e: e["timestamp"])

    # Print report
    print_report(entries, from_ms, to_ms, rules)

    # Exit code based on firing alerts
    has_firing = any(is_firing(e) for e in entries)
    sys.exit(1 if has_firing else 0)


if __name__ == "__main__":
    main()
