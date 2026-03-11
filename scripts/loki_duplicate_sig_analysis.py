#!/usr/bin/env python3
"""
Analyze "Ignoring duplicate partial signature" spam across multiple clusters
using Grafana Loki queries.

Usage:
  export $(cat /Users/oisinkyne/code/ObolNetwork/charon/.env | xargs)
  python3 scripts/loki_duplicate_sig_analysis.py
"""

import json
import os
import sys
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone

# --- Configuration ---
GRAFANA_BASE = "https://grafana.monitoring.gcp.obol.tech"
LOKI_PROXY = "/api/datasources/proxy/14/loki/api/v1"
TOKEN = os.environ.get("OBOL_GRAFANA_API_TOKEN", "")

if not TOKEN:
    print("ERROR: OBOL_GRAFANA_API_TOKEN not set. Run:")
    print("  export $(cat /Users/oisinkyne/code/ObolNetwork/charon/.env | xargs)")
    sys.exit(1)

CLUSTERS = [
    "Lido x Obol: Azure Albatross",
    "Lido x Obol: Arctic Amarok",
    "Etherfi-Obol-curated-EU-03",
    "Lido x Obol: Bold Banshee",
]

# Time windows (nanosecond epoch for Loki)
# Inflection analysis: before (07:00-09:00) vs after (09:00-12:00) on 2026-03-09
BEFORE_START = int(datetime(2026, 3, 9, 7, 0, 0, tzinfo=timezone.utc).timestamp() * 1e9)
BEFORE_END   = int(datetime(2026, 3, 9, 9, 0, 0, tzinfo=timezone.utc).timestamp() * 1e9)
AFTER_START  = int(datetime(2026, 3, 9, 9, 0, 0, tzinfo=timezone.utc).timestamp() * 1e9)
AFTER_END    = int(datetime(2026, 3, 9, 12, 0, 0, tzinfo=timezone.utc).timestamp() * 1e9)

# Wider window for duty-type breakdown
WIDE_START = int(datetime(2026, 3, 9, 7, 0, 0, tzinfo=timezone.utc).timestamp() * 1e9)
WIDE_END   = int(datetime(2026, 3, 9, 12, 0, 0, tzinfo=timezone.utc).timestamp() * 1e9)


def loki_query_range(query, start_ns, end_ns, step="60s", limit=5000):
    """Execute a Loki query_range and return parsed JSON."""
    params = urllib.parse.urlencode({
        "query": query,
        "start": str(start_ns),
        "end": str(end_ns),
        "step": step,
        "limit": str(limit),
    })
    url = f"{GRAFANA_BASE}{LOKI_PROXY}/query_range?{params}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        print(f"  HTTP {e.code}: {body[:300]}")
        return None
    except Exception as e:
        print(f"  Error: {e}")
        return None


def loki_query(query, start_ns, end_ns, limit=5000):
    """Execute a Loki instant-style log query (query_range for logs)."""
    params = urllib.parse.urlencode({
        "query": query,
        "start": str(start_ns),
        "end": str(end_ns),
        "limit": str(limit),
        "direction": "forward",
    })
    url = f"{GRAFANA_BASE}{LOKI_PROXY}/query_range?{params}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        print(f"  HTTP {e.code}: {body[:300]}")
        return None
    except Exception as e:
        print(f"  Error: {e}")
        return None


def count_from_metric_result(result):
    """Sum up values from a metric query result (rate/count_over_time)."""
    if not result or result.get("status") != "success":
        return None
    data = result.get("data", {})
    results = data.get("result", [])
    total = 0
    for series in results:
        values = series.get("values", [])
        for ts, val in values:
            total += float(val)
    return total


def extract_log_lines(result):
    """Extract raw log lines from a streams result."""
    if not result or result.get("status") != "success":
        return []
    data = result.get("data", {})
    results = data.get("result", [])
    lines = []
    for stream in results:
        for ts, line in stream.get("values", []):
            lines.append(line)
    return lines


def parse_ts_from_line(line):
    """Extract ts= timestamp from a log line."""
    idx = line.find("ts=")
    if idx == -1:
        return None
    rest = line[idx+3:]
    # Find end of timestamp (space or end of string)
    end = rest.find(" ")
    if end == -1:
        end = len(rest)
    ts_str = rest[:end].strip('"')
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except:
        return None


def parse_duty_from_line(line):
    """Extract duty type from a log line (e.g., duty=prepare_aggregator)."""
    idx = line.find("duty=")
    if idx == -1:
        # Try looking for duty type in other formats
        for dtype in ["prepare_aggregator", "attester", "proposer", "sync_contribution",
                       "sync_aggregator", "builder_proposer", "prepare_sync_contribution"]:
            if dtype in line:
                return dtype
        return "unknown"
    rest = line[idx+5:]
    end = rest.find(" ")
    if end == -1:
        end = len(rest)
    return rest[:end].strip('"')


# ============================================================
print("=" * 80)
print("LOKI ANALYSIS: 'Ignoring duplicate partial signature' spam")
print("Inflection point analysis: 2026-03-09 09:00 UTC")
print("=" * 80)

# --- TASK 1: Rate comparison before vs after inflection point ---
print("\n" + "=" * 80)
print("TASK 1: Rate of duplicate signature messages - Before vs After inflection")
print("  Before: 07:00-09:00 UTC | After: 09:00-12:00 UTC")
print("=" * 80)

for cluster in CLUSTERS:
    print(f"\n--- Cluster: {cluster} ---")
    # Use count_over_time with a log filter
    # Escape quotes in cluster name for LogQL
    escaped = cluster.replace('"', '\\"')

    # Query: count log lines matching the duplicate sig message per 30m buckets
    base_filter = f'{{cluster="{escaped}"}} |= "Ignoring duplicate partial signature"'

    # Before period - use count_over_time
    q_before = f'count_over_time({base_filter}[2h])'
    print(f"  Querying BEFORE period...")
    res_before = loki_query_range(q_before, BEFORE_START, BEFORE_END, step="7200s")
    count_before = count_from_metric_result(res_before)

    # After period
    q_after = f'count_over_time({base_filter}[3h])'
    print(f"  Querying AFTER period...")
    res_after = loki_query_range(q_after, AFTER_START, AFTER_END, step="10800s")
    count_after = count_from_metric_result(res_after)

    if count_before is not None and count_after is not None:
        ratio = count_after / count_before if count_before > 0 else float('inf')
        print(f"  BEFORE (07-09 UTC): {count_before:.0f} messages (2h window)")
        print(f"  AFTER  (09-12 UTC): {count_after:.0f} messages (3h window)")
        before_rate = count_before / 2 if count_before else 0
        after_rate = count_after / 3 if count_after else 0
        print(f"  Hourly rate BEFORE: {before_rate:.0f}/hr")
        print(f"  Hourly rate AFTER:  {after_rate:.0f}/hr")
        if before_rate > 0:
            print(f"  Rate change: {((after_rate - before_rate) / before_rate * 100):+.1f}%")
        else:
            print(f"  Rate change: N/A (no messages before)")
    else:
        print(f"  Could not retrieve data. Trying alternative label...")
        # Try with cluster_name label instead
        base_filter2 = f'{{cluster_name="{escaped}"}} |= "Ignoring duplicate partial signature"'
        q_before2 = f'count_over_time({base_filter2}[2h])'
        q_after2 = f'count_over_time({base_filter2}[3h])'
        res_before2 = loki_query_range(q_before2, BEFORE_START, BEFORE_END, step="7200s")
        res_after2 = loki_query_range(q_after2, AFTER_START, AFTER_END, step="10800s")
        count_before2 = count_from_metric_result(res_before2)
        count_after2 = count_from_metric_result(res_after2)
        if count_before2 is not None:
            ratio = count_after2 / count_before2 if count_before2 > 0 else float('inf')
            print(f"  (via cluster_name label)")
            print(f"  BEFORE (07-09 UTC): {count_before2:.0f} messages")
            print(f"  AFTER  (09-12 UTC): {count_after2:.0f} messages")
        else:
            print(f"  Still no data. Label might differ - check available labels.")


# --- TASK 2: During timeout slots, is output dominated by duplicate sig spam? ---
print("\n" + "=" * 80)
print("TASK 2: Log composition during timeout windows")
print("  Checking if duplicate sig spam dominates during timeout periods")
print("=" * 80)

for cluster in CLUSTERS:
    print(f"\n--- Cluster: {cluster} ---")
    escaped = cluster.replace('"', '\\"')

    # Get total log volume and duplicate sig volume in the post-inflection window
    # Total logs
    q_total = f'count_over_time({{cluster="{escaped}"}}[3h])'
    q_dup = f'count_over_time({{cluster="{escaped}"}} |= "Ignoring duplicate partial signature"[3h])'
    q_timeout = f'count_over_time({{cluster="{escaped}"}} |= "timeout"[3h])'

    print(f"  Querying log composition (09:00-12:00 UTC)...")
    res_total = loki_query_range(q_total, AFTER_START, AFTER_END, step="10800s")
    res_dup = loki_query_range(q_dup, AFTER_START, AFTER_END, step="10800s")
    res_timeout = loki_query_range(q_timeout, AFTER_START, AFTER_END, step="10800s")

    total = count_from_metric_result(res_total)
    dup = count_from_metric_result(res_dup)
    timeout = count_from_metric_result(res_timeout)

    if total is not None and total > 0:
        dup_pct = (dup / total * 100) if dup else 0
        timeout_pct = (timeout / total * 100) if timeout else 0
        print(f"  Total log lines:        {total:.0f}")
        print(f"  Duplicate sig lines:    {dup:.0f} ({dup_pct:.1f}%)")
        print(f"  Timeout-related lines:  {timeout:.0f} ({timeout_pct:.1f}%)")
        if dup_pct > 30:
            print(f"  ** CONFIRMED: Duplicate sig spam dominates log output ({dup_pct:.1f}%)")
        elif dup_pct > 10:
            print(f"  ** NOTABLE: Significant duplicate sig presence ({dup_pct:.1f}%)")
        else:
            print(f"  Duplicate sig messages are not dominant ({dup_pct:.1f}%)")
    else:
        print(f"  No data or zero total. Trying cluster_name label...")
        q_total2 = f'count_over_time({{cluster_name="{escaped}"}}[3h])'
        q_dup2 = f'count_over_time({{cluster_name="{escaped}"}} |= "Ignoring duplicate partial signature"[3h])'
        q_timeout2 = f'count_over_time({{cluster_name="{escaped}"}} |= "timeout"[3h])'
        res_total2 = loki_query_range(q_total2, AFTER_START, AFTER_END, step="10800s")
        res_dup2 = loki_query_range(q_dup2, AFTER_START, AFTER_END, step="10800s")
        res_timeout2 = loki_query_range(q_timeout2, AFTER_START, AFTER_END, step="10800s")
        total2 = count_from_metric_result(res_total2)
        dup2 = count_from_metric_result(res_dup2)
        timeout2 = count_from_metric_result(res_timeout2)
        if total2 and total2 > 0:
            dup_pct2 = (dup2 / total2 * 100) if dup2 else 0
            timeout_pct2 = (timeout2 / total2 * 100) if timeout2 else 0
            print(f"  (via cluster_name label)")
            print(f"  Total log lines:        {total2:.0f}")
            print(f"  Duplicate sig lines:    {dup2:.0f} ({dup_pct2:.1f}%)")
            print(f"  Timeout-related lines:  {timeout2:.0f} ({timeout_pct2:.1f}%)")
        else:
            print(f"  Still no data.")


# --- TASK 3: Duty type breakdown of duplicate sig messages ---
print("\n" + "=" * 80)
print("TASK 3: Duty type breakdown of duplicate signature messages")
print("  Checking if prepare_aggregator is specifically affected")
print("=" * 80)

DUTY_TYPES = [
    "prepare_aggregator",
    "attester",
    "proposer",
    "sync_contribution",
    "sync_aggregator",
    "builder_proposer",
    "prepare_sync_contribution",
]

for cluster in CLUSTERS:
    print(f"\n--- Cluster: {cluster} ---")
    escaped = cluster.replace('"', '\\"')

    duty_counts = {}
    for duty in DUTY_TYPES:
        q = f'count_over_time({{cluster="{escaped}"}} |= "Ignoring duplicate partial signature" |= "{duty}"[5h])'
        res = loki_query_range(q, WIDE_START, WIDE_END, step="18000s")
        cnt = count_from_metric_result(res)
        if cnt is None:
            # Try cluster_name
            q2 = f'count_over_time({{cluster_name="{escaped}"}} |= "Ignoring duplicate partial signature" |= "{duty}"[5h])'
            res2 = loki_query_range(q2, WIDE_START, WIDE_END, step="18000s")
            cnt = count_from_metric_result(res2)
        duty_counts[duty] = cnt if cnt is not None else 0

    total_typed = sum(duty_counts.values())
    print(f"  Duty type breakdown (07:00-12:00 UTC):")
    for duty, cnt in sorted(duty_counts.items(), key=lambda x: -x[1]):
        pct = (cnt / total_typed * 100) if total_typed > 0 else 0
        bar = "#" * int(pct / 2)
        print(f"    {duty:<30s}: {cnt:>8.0f} ({pct:5.1f}%) {bar}")

    if total_typed > 0:
        top_duty = max(duty_counts, key=duty_counts.get)
        top_pct = duty_counts[top_duty] / total_typed * 100
        if top_duty == "prepare_aggregator" and top_pct > 50:
            print(f"  ** CONFIRMED: prepare_aggregator dominates ({top_pct:.1f}%)")
        elif top_pct > 50:
            print(f"  ** Top duty type: {top_duty} ({top_pct:.1f}%)")
        else:
            print(f"  ** Multiple duty types affected - no single dominant type")
    else:
        print(f"  No duty-typed duplicate sig messages found.")


# --- TASK 3b: Sample actual log lines to verify duty extraction ---
print("\n" + "=" * 80)
print("TASK 3b: Sample log lines for duty type verification")
print("=" * 80)

# Just sample from one cluster
sample_cluster = CLUSTERS[0]
escaped = sample_cluster.replace('"', '\\"')
q_sample = f'{{cluster="{escaped}"}} |= "Ignoring duplicate partial signature"'
print(f"  Sampling from: {sample_cluster}")
res_sample = loki_query(q_sample, AFTER_START, AFTER_END, limit=20)
lines = extract_log_lines(res_sample)
if not lines:
    q_sample2 = f'{{cluster_name="{escaped}"}} |= "Ignoring duplicate partial signature"'
    res_sample2 = loki_query(q_sample2, AFTER_START, AFTER_END, limit=20)
    lines = extract_log_lines(res_sample2)

if lines:
    print(f"  Got {len(lines)} sample lines. Parsing duty types and timestamps:")
    duty_dist = {}
    for line in lines[:20]:
        ts = parse_ts_from_line(line)
        duty = parse_duty_from_line(line)
        duty_dist[duty] = duty_dist.get(duty, 0) + 1
        ts_str = ts.strftime("%H:%M:%S") if ts else "?"
        # Print truncated line
        print(f"    [{ts_str}] duty={duty}  |  {line[:120]}...")
    print(f"\n  Duty distribution in sample:")
    for d, c in sorted(duty_dist.items(), key=lambda x: -x[1]):
        print(f"    {d}: {c}")
else:
    print(f"  No sample lines retrieved.")


print("\n" + "=" * 80)
print("ANALYSIS COMPLETE")
print("=" * 80)
