#!/usr/bin/env python3
"""
Fetches alert history for Charon Kurtosis alerts from Grafana.
Requires OBOL_GRAFANA_API_TOKEN environment variable.
Usage: python kurtosis_alerts.py --from <start> --to <end>
  --from: Start time (ISO 8601 e.g. 2024-03-01T00:00:00Z, or epoch seconds)
  --to:   End time (ISO 8601 e.g. 2024-03-02T00:00:00Z, or epoch seconds)

Outputs JSON array of alert history entries to stdout.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

GRAFANA_BASE = "https://grafana.monitoring.gcp.obol.tech"
TARGET_FOLDER = "Charon Kurtosis Alerts"


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
            print(f"Error: HTTP {e.code} fetching {url}", file=sys.stderr)
        return None
    except urllib.error.URLError as e:
        if not silent:
            print(f"Error: {e.reason}", file=sys.stderr)
        return None
    except Exception as e:
        if not silent:
            print(f"Error: {e}", file=sys.stderr)
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
        print(f"Error: cannot parse timestamp '{value}'", file=sys.stderr)
        sys.exit(1)


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
        print(f"Warning: folder '{TARGET_FOLDER}' not found", file=sys.stderr)
        print(json.dumps([]))
        sys.exit(0)

    # Get alert rules in the folder
    rules = fetch_alert_rules(headers, folder_uid)
    if not rules:
        print(f"Warning: no alert rules found in '{TARGET_FOLDER}'", file=sys.stderr)
        print(json.dumps([]))
        sys.exit(0)

    rule_titles = {r["title"] for r in rules}
    print(f"Found {len(rules)} alert rule(s): {', '.join(sorted(rule_titles))}", file=sys.stderr)

    # Fetch annotations and filter by rule titles
    annotations = fetch_annotations(headers, from_ms, to_ms)
    matching = [a for a in annotations if a.get("alertName") in rule_titles]

    # Format and sort by timestamp
    entries = [format_alert_entry(a) for a in matching]
    entries.sort(key=lambda e: e["timestamp"])

    print(json.dumps(entries, indent=2))


if __name__ == "__main__":
    main()
