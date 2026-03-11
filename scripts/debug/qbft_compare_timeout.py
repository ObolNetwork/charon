#!/usr/bin/env python3
"""
Diagnose QBFT compare timeout issues ("timeout waiting for local data").

This timeout occurs when a node receives the leader's pre-prepare but hasn't
finished fetching its own unsigned data from the beacon node. The round timer
expires while the Compare function waits for inputValueSourceCh (VerifyCh).

Requires OBOL_GRAFANA_API_TOKEN environment variable.

Usage:
  python qbft_compare_timeout.py <cluster_name> [options]

  Options:
    --network NETWORK     Network name (default: mainnet)
    --hours HOURS         Hours to look back (default: 24)
    --slot SLOT           Analyze a specific slot instead of a time range
    --limit LIMIT         Max log entries to fetch (default: 5000)

Outputs JSON with:
  - timeout_events: parsed timeout occurrences with peer, slot, duty, round info
  - correlated_events: BN call timings, consensus outcomes for affected slots
  - metrics: aggregate Prometheus metrics (consensus timeouts, BN latency, decided rounds)
  - summary: high-level analysis of patterns
"""

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

GRAFANA_BASE = "https://grafana.monitoring.gcp.obol.tech"

GENESIS_TIME = {
    "mainnet": 1606824023,
    "hoodi": 1742212800,
    "sepolia": 1655733600,
}

SLOTS_PER_EPOCH = 32
SECONDS_PER_SLOT = 12


def get_auth_header() -> dict:
    token = os.environ.get("OBOL_GRAFANA_API_TOKEN")
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def fetch_json(url: str, headers: dict, silent: bool = False) -> dict | None:
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


def discover_datasources(headers: dict) -> tuple[str | None, str | None]:
    url = f"{GRAFANA_BASE}/api/datasources"
    datasources = fetch_json(url, headers)
    if not datasources:
        return None, None

    prom_id = None
    loki_id = None
    for ds in datasources:
        if ds.get("type") == "prometheus" and ds.get("name") == "prometheus":
            prom_id = ds.get("id")
        if ds.get("type") == "loki" and ds.get("name") == "Loki":
            loki_id = ds.get("id")

    prom_url = f"{GRAFANA_BASE}/api/datasources/proxy/{prom_id}/api/v1/" if prom_id else None
    loki_url = f"{GRAFANA_BASE}/api/datasources/proxy/{loki_id}/loki/api/v1/" if loki_id else None
    return prom_url, loki_url


def prom_query(prom_url: str, headers: dict, query: str) -> dict | None:
    url = f"{prom_url}query?query={urllib.parse.quote(query)}"
    return fetch_json(url, headers, silent=True)


def prom_query_range(prom_url: str, headers: dict, query: str, start: int, end: int, step: str = "60s") -> dict | None:
    params = urllib.parse.urlencode({
        "query": query,
        "start": str(start),
        "end": str(end),
        "step": step,
    })
    url = f"{prom_url}query_range?{params}"
    return fetch_json(url, headers, silent=True)


def loki_query(loki_url: str, headers: dict, logql: str, start_ns: int, end_ns: int, limit: int = 5000) -> dict | None:
    params = urllib.parse.urlencode({
        "query": logql,
        "start": str(start_ns),
        "end": str(end_ns),
        "limit": str(limit),
        "direction": "forward",
    })
    url = f"{loki_url}query_range?{params}"
    return fetch_json(url, headers, silent=True)


def extract_logfmt(line: str, field: str) -> str:
    m = re.search(rf'{field}="([^"]*)"', line)
    if m:
        return m.group(1)
    m = re.search(rf"{field}=(\S+)", line)
    if m:
        return m.group(1)
    return ""


def parse_embedded_ts(line: str) -> int | None:
    """Parse the embedded ts= field from a logfmt line, returning nanoseconds since epoch.

    Charon logs include ts=2026-03-09T20:53:59.123456789Z which is the actual application
    timestamp. This is more accurate than the Loki receipt timestamp which can have
    significant skew (0.5-2s observed).
    """
    m = re.search(r'ts=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d+)Z', line)
    if m:
        dt = datetime.fromisoformat(m.group(1) + "+00:00")
        base_ns = int(dt.timestamp()) * 1_000_000_000
        frac = m.group(2)
        # Pad or truncate to 9 digits (nanoseconds)
        frac_ns = int(frac.ljust(9, "0")[:9])
        return base_ns + frac_ns
    # Fallback: try without fractional seconds
    m = re.search(r'ts=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})Z', line)
    if m:
        dt = datetime.fromisoformat(m.group(1) + "+00:00")
        return int(dt.timestamp()) * 1_000_000_000
    return None


def get_event_timestamp_ns(loki_ts_str: str, line: str) -> int:
    """Get the best available timestamp in nanoseconds: embedded ts= preferred over Loki timestamp."""
    embedded = parse_embedded_ts(line)
    if embedded is not None:
        return embedded
    return int(loki_ts_str)


def parse_duty_string(duty_str: str) -> dict:
    """Parse duty string like '1234/attester' into components."""
    parts = duty_str.split("/")
    if len(parts) == 2:
        try:
            return {"slot": int(parts[0]), "type": parts[1]}
        except ValueError:
            pass
    return {"slot": 0, "type": duty_str}


def slot_to_time(slot: int, network: str) -> str | None:
    genesis = GENESIS_TIME.get(network)
    if not genesis:
        return None
    ts = genesis + slot * SECONDS_PER_SLOT
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def query_timeout_events(loki_url: str, headers: dict, cluster_name: str, network: str,
                         start_ns: int, end_ns: int, limit: int) -> list[dict]:
    """Query Loki for compare timeout warnings."""
    logql = (
        f'{{cluster_name="{cluster_name}",cluster_network="{network}"}} '
        f'|= `timeout waiting for local data`'
    )
    raw = loki_query(loki_url, headers, logql, start_ns, end_ns, limit)
    if not raw:
        return []

    events = []
    for stream in raw.get("data", {}).get("result", []):
        peer = stream.get("stream", {}).get("cluster_peer", "unknown")
        for ts_str, line in stream.get("values", []):
            duty_str = extract_logfmt(line, "duty")
            duty = parse_duty_string(duty_str)
            events.append({
                "timestamp_ns": get_event_timestamp_ns(ts_str, line),
                "peer": peer,
                "duty": duty_str,
                "slot": duty["slot"],
                "duty_type": duty["type"],
            })

    events.sort(key=lambda x: x["timestamp_ns"])
    return events


def query_round_changes(loki_url: str, headers: dict, cluster_name: str, network: str,
                        start_ns: int, end_ns: int, limit: int) -> list[dict]:
    """Query Loki for QBFT round change events."""
    logql = (
        f'{{cluster_name="{cluster_name}",cluster_network="{network}"}} '
        f'|= `QBFT round changed`'
    )
    raw = loki_query(loki_url, headers, logql, start_ns, end_ns, limit)
    if not raw:
        return []

    events = []
    for stream in raw.get("data", {}).get("result", []):
        peer = stream.get("stream", {}).get("cluster_peer", "unknown")
        for ts_str, line in stream.get("values", []):
            duty_str = extract_logfmt(line, "duty")
            duty = parse_duty_string(duty_str)
            events.append({
                "timestamp_ns": get_event_timestamp_ns(ts_str, line),
                "peer": peer,
                "duty": duty_str,
                "slot": duty["slot"],
                "duty_type": duty["type"],
                "round": extract_logfmt(line, "round"),
                "new_round": extract_logfmt(line, "new_round"),
                "rule": extract_logfmt(line, "rule"),
                "timeout_reason": extract_logfmt(line, "timeout_reason"),
            })

    events.sort(key=lambda x: x["timestamp_ns"])
    return events


def query_consensus_decided(loki_url: str, headers: dict, cluster_name: str, network: str,
                            start_ns: int, end_ns: int, limit: int) -> list[dict]:
    """Query Loki for QBFT consensus decided events."""
    logql = (
        f'{{cluster_name="{cluster_name}",cluster_network="{network}"}} '
        f'|= `QBFT consensus decided`'
    )
    raw = loki_query(loki_url, headers, logql, start_ns, end_ns, limit)
    if not raw:
        return []

    events = []
    for stream in raw.get("data", {}).get("result", []):
        peer = stream.get("stream", {}).get("cluster_peer", "unknown")
        for ts_str, line in stream.get("values", []):
            duty_str = extract_logfmt(line, "duty")
            duty = parse_duty_string(duty_str)
            events.append({
                "timestamp_ns": get_event_timestamp_ns(ts_str, line),
                "peer": peer,
                "duty": duty_str,
                "slot": duty["slot"],
                "duty_type": duty["type"],
                "round": extract_logfmt(line, "round"),
                "leader_name": extract_logfmt(line, "leader_name"),
                "leader_index": extract_logfmt(line, "leader_index"),
            })

    events.sort(key=lambda x: x["timestamp_ns"])
    return events


def query_consensus_timeouts(loki_url: str, headers: dict, cluster_name: str, network: str,
                             start_ns: int, end_ns: int, limit: int) -> list[dict]:
    """Query Loki for full consensus timeout errors."""
    logql = (
        f'{{cluster_name="{cluster_name}",cluster_network="{network}"}} '
        f'|= `consensus timeout`'
    )
    raw = loki_query(loki_url, headers, logql, start_ns, end_ns, limit)
    if not raw:
        return []

    events = []
    for stream in raw.get("data", {}).get("result", []):
        peer = stream.get("stream", {}).get("cluster_peer", "unknown")
        for ts_str, line in stream.get("values", []):
            duty_str = extract_logfmt(line, "duty")
            duty = parse_duty_string(duty_str)
            events.append({
                "timestamp_ns": get_event_timestamp_ns(ts_str, line),
                "peer": peer,
                "duty": duty_str,
                "slot": duty["slot"],
                "duty_type": duty["type"],
            })

    events.sort(key=lambda x: x["timestamp_ns"])
    return events


def query_bn_call_logs(loki_url: str, headers: dict, cluster_name: str, network: str,
                       start_ns: int, end_ns: int, limit: int) -> list[dict]:
    """Query Loki for beacon node call timing logs."""
    logql = (
        f'{{cluster_name="{cluster_name}",cluster_network="{network}"}} '
        f'|~ `Beacon node call finished|Beacon node call took longer|Calling beacon node endpoint`'
    )
    raw = loki_query(loki_url, headers, logql, start_ns, end_ns, limit)
    if not raw:
        return []

    events = []
    for stream in raw.get("data", {}).get("result", []):
        peer = stream.get("stream", {}).get("cluster_peer", "unknown")
        for ts_str, line in stream.get("values", []):
            msg = extract_logfmt(line, "msg")
            duty_str = extract_logfmt(line, "duty")
            duty = parse_duty_string(duty_str)

            event_type = ""
            if "Calling beacon node endpoint" in msg:
                event_type = "bn_call_start"
            elif "took longer" in msg:
                event_type = "bn_call_slow"
            elif "call finished" in msg:
                event_type = "bn_call_done"

            events.append({
                "timestamp_ns": get_event_timestamp_ns(ts_str, line),
                "peer": peer,
                "duty": duty_str,
                "slot": duty["slot"],
                "duty_type": duty["type"],
                "event_type": event_type,
                "endpoint": extract_logfmt(line, "endpoint"),
                "rtt": extract_logfmt(line, "rtt"),
            })

    events.sort(key=lambda x: x["timestamp_ns"])
    return events


def query_slot_logs(loki_url: str, headers: dict, cluster_name: str, network: str,
                    slot: int, limit: int) -> list[dict]:
    """Query all consensus-related logs for a specific slot."""
    genesis = GENESIS_TIME.get(network)
    if not genesis:
        return []

    slot_ts = genesis + slot * SECONDS_PER_SLOT
    start_ns = (slot_ts - 15) * 1_000_000_000
    end_ns = (slot_ts + 120) * 1_000_000_000

    logql = (
        f'{{cluster_name="{cluster_name}",cluster_network="{network}"}} '
        f'|~ `{slot}/attester|{slot}/proposer|{slot}/sync_contribution|slot={slot}|block_slot={slot}` '
        f'|~ `timeout waiting for local|QBFT|consensus|Beacon node call|Calling beacon`'
    )
    raw = loki_query(loki_url, headers, logql, start_ns, end_ns, limit)
    if not raw:
        return []

    events = []
    for stream in raw.get("data", {}).get("result", []):
        peer = stream.get("stream", {}).get("cluster_peer", "unknown")
        for ts_str, line in stream.get("values", []):
            msg = extract_logfmt(line, "msg")
            level = extract_logfmt(line, "level")
            duty_str = extract_logfmt(line, "duty")
            event_ts_ns = get_event_timestamp_ns(ts_str, line)
            offset_s = (event_ts_ns / 1_000_000_000) - slot_ts

            events.append({
                "offset_s": round(offset_s, 3),
                "timestamp_ns": event_ts_ns,
                "peer": peer,
                "level": level,
                "msg": msg,
                "duty": duty_str,
                "round": extract_logfmt(line, "round"),
                "new_round": extract_logfmt(line, "new_round"),
                "rule": extract_logfmt(line, "rule"),
                "timeout_reason": extract_logfmt(line, "timeout_reason"),
                "endpoint": extract_logfmt(line, "endpoint"),
                "rtt": extract_logfmt(line, "rtt"),
                "leader_name": extract_logfmt(line, "leader_name"),
                "leader_index": extract_logfmt(line, "leader_index"),
            })

    events.sort(key=lambda x: x["timestamp_ns"])
    return events


def query_prometheus_metrics(prom_url: str, headers: dict, cluster_name: str, network: str,
                             start: int, end: int) -> dict:
    """Query Prometheus for aggregate consensus and BN metrics."""
    metrics = {}

    # Consensus timeout rate
    q = f'sum(rate(core_consensus_timeout_total{{cluster_name="{cluster_name}",cluster_network="{network}"}}[1h])) by (duty, timer)'
    result = prom_query(prom_url, headers, q)
    if result and result.get("data", {}).get("result"):
        metrics["consensus_timeout_rate_per_hour"] = [
            {
                "duty": r.get("metric", {}).get("duty", "?"),
                "timer": r.get("metric", {}).get("timer", "?"),
                "rate": float(r.get("value", [0, 0])[1]),
            }
            for r in result["data"]["result"]
        ]

    # Consensus decided rounds
    q = f'core_consensus_decided_rounds{{cluster_name="{cluster_name}",cluster_network="{network}"}}'
    result = prom_query(prom_url, headers, q)
    if result and result.get("data", {}).get("result"):
        metrics["last_decided_rounds"] = [
            {
                "duty": r.get("metric", {}).get("duty", "?"),
                "timer": r.get("metric", {}).get("timer", "?"),
                "round": float(r.get("value", [0, 0])[1]),
            }
            for r in result["data"]["result"]
        ]

    # Consensus duration
    q = f'histogram_quantile(0.99, sum(rate(core_consensus_duration_seconds_bucket{{cluster_name="{cluster_name}",cluster_network="{network}"}}[1h])) by (duty, timer, le))'
    result = prom_query(prom_url, headers, q)
    if result and result.get("data", {}).get("result"):
        metrics["consensus_duration_p99"] = [
            {
                "duty": r.get("metric", {}).get("duty", "?"),
                "timer": r.get("metric", {}).get("timer", "?"),
                "seconds": float(r.get("value", [0, 0])[1]),
            }
            for r in result["data"]["result"]
        ]

    # BN call latency p99
    q = f'histogram_quantile(0.99, sum(rate(app_eth2_latency_seconds_bucket{{cluster_name="{cluster_name}",cluster_network="{network}"}}[1h])) by (endpoint, le))'
    result = prom_query(prom_url, headers, q)
    if result and result.get("data", {}).get("result"):
        metrics["bn_latency_p99"] = [
            {
                "endpoint": r.get("metric", {}).get("endpoint", "?"),
                "seconds": float(r.get("value", [0, 0])[1]),
            }
            for r in result["data"]["result"]
            if not (r.get("value", [0, "NaN"])[1] == "NaN")
        ]

    # BN error rate
    q = f'sum(rate(app_eth2_errors_total{{cluster_name="{cluster_name}",cluster_network="{network}"}}[1h])) by (endpoint)'
    result = prom_query(prom_url, headers, q)
    if result and result.get("data", {}).get("result"):
        metrics["bn_error_rate_per_hour"] = [
            {
                "endpoint": r.get("metric", {}).get("endpoint", "?"),
                "rate": float(r.get("value", [0, 0])[1]),
            }
            for r in result["data"]["result"]
            if float(r.get("value", [0, 0])[1]) > 0
        ]

    # Total consensus timeouts
    q = f'sum(core_consensus_timeout_total{{cluster_name="{cluster_name}",cluster_network="{network}"}}) by (duty, timer)'
    result = prom_query(prom_url, headers, q)
    if result and result.get("data", {}).get("result"):
        metrics["consensus_timeout_totals"] = [
            {
                "duty": r.get("metric", {}).get("duty", "?"),
                "timer": r.get("metric", {}).get("timer", "?"),
                "total": float(r.get("value", [0, 0])[1]),
            }
            for r in result["data"]["result"]
        ]

    return metrics


def correlate_events(timeout_events: list, round_changes: list, decided_events: list,
                     bn_calls: list, consensus_timeouts: list) -> dict:
    """Correlate timeout events with round changes, decisions, and BN calls."""
    # Group by slot for correlation
    affected_slots = set()
    for ev in timeout_events:
        affected_slots.add((ev["slot"], ev["duty_type"]))

    correlations = {}
    for slot, duty_type in sorted(affected_slots):
        key = f"{slot}/{duty_type}"
        corr = {
            "slot": slot,
            "duty_type": duty_type,
            "timeout_peers": [],
            "round_changes": [],
            "decided": None,
            "full_timeout": False,
            "bn_calls": [],
        }

        # Timeout peers
        for ev in timeout_events:
            if ev["slot"] == slot and ev["duty_type"] == duty_type:
                corr["timeout_peers"].append(ev["peer"])

        # Round changes for this slot
        for ev in round_changes:
            if ev["slot"] == slot and ev["duty_type"] == duty_type:
                corr["round_changes"].append({
                    "peer": ev["peer"],
                    "round": ev["round"],
                    "new_round": ev["new_round"],
                    "rule": ev["rule"],
                    "timeout_reason": ev["timeout_reason"],
                })

        # Did consensus decide?
        for ev in decided_events:
            if ev["slot"] == slot and ev["duty_type"] == duty_type:
                corr["decided"] = {
                    "round": ev["round"],
                    "leader_name": ev["leader_name"],
                    "leader_index": ev["leader_index"],
                }
                break

        # Full consensus timeout?
        for ev in consensus_timeouts:
            if ev["slot"] == slot and ev["duty_type"] == duty_type:
                corr["full_timeout"] = True
                break

        # BN calls for this slot
        for ev in bn_calls:
            if ev["slot"] == slot and ev["duty_type"] == duty_type:
                corr["bn_calls"].append({
                    "peer": ev["peer"],
                    "event_type": ev["event_type"],
                    "endpoint": ev["endpoint"],
                    "rtt": ev["rtt"],
                })

        corr["timeout_peers"] = sorted(set(corr["timeout_peers"]))
        correlations[key] = corr

    return correlations


def build_summary(timeout_events: list, correlations: dict, metrics: dict, network: str) -> dict:
    """Build a high-level summary of the analysis."""
    summary = {
        "total_timeout_events": len(timeout_events),
        "affected_slots": len(correlations),
        "affected_duty_types": {},
        "affected_peers": {},
        "slots_that_decided": 0,
        "slots_that_fully_timed_out": 0,
        "decided_round_distribution": {},
        "pattern_analysis": [],
    }

    for ev in timeout_events:
        dt = ev["duty_type"]
        summary["affected_duty_types"][dt] = summary["affected_duty_types"].get(dt, 0) + 1
        p = ev["peer"]
        summary["affected_peers"][p] = summary["affected_peers"].get(p, 0) + 1

    for key, corr in correlations.items():
        if corr["decided"]:
            summary["slots_that_decided"] += 1
            r = corr["decided"]["round"]
            summary["decided_round_distribution"][r] = summary["decided_round_distribution"].get(r, 0) + 1
        if corr["full_timeout"]:
            summary["slots_that_fully_timed_out"] += 1

    # Pattern analysis
    if summary["total_timeout_events"] > 0:
        # Check if one peer is disproportionately affected
        max_peer = max(summary["affected_peers"].items(), key=lambda x: x[1]) if summary["affected_peers"] else None
        if max_peer and max_peer[1] > summary["total_timeout_events"] * 0.5:
            summary["pattern_analysis"].append(
                f"Peer '{max_peer[0]}' accounts for {max_peer[1]}/{summary['total_timeout_events']} "
                f"({100*max_peer[1]//summary['total_timeout_events']}%) of timeouts - likely has a slow BN"
            )

        # Check if mostly attester (expected)
        if "attester" in summary["affected_duty_types"]:
            att_pct = summary["affected_duty_types"]["attester"] / summary["total_timeout_events"]
            if att_pct > 0.9:
                summary["pattern_analysis"].append(
                    "Timeouts are predominantly on attester duties (expected - only duty type with compare enabled)"
                )

        # Check recovery rate
        if summary["affected_slots"] > 0:
            recovery_rate = summary["slots_that_decided"] / summary["affected_slots"]
            if recovery_rate > 0.9:
                summary["pattern_analysis"].append(
                    f"High recovery rate: {summary['slots_that_decided']}/{summary['affected_slots']} "
                    f"({100*recovery_rate:.0f}%) slots eventually reached consensus despite compare timeout"
                )
            elif recovery_rate < 0.5:
                summary["pattern_analysis"].append(
                    f"Low recovery rate: only {summary['slots_that_decided']}/{summary['affected_slots']} "
                    f"({100*recovery_rate:.0f}%) slots reached consensus - indicates systemic issue"
                )

        # Check BN latency from metrics
        if metrics.get("bn_latency_p99"):
            slow_endpoints = [m for m in metrics["bn_latency_p99"] if m["seconds"] > 0.5]
            if slow_endpoints:
                summary["pattern_analysis"].append(
                    f"Slow BN endpoints detected (p99 > 500ms): "
                    + ", ".join(f"{e['endpoint']}={e['seconds']:.2f}s" for e in slow_endpoints[:5])
                )

    return summary


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Diagnose QBFT compare timeout issues")
    parser.add_argument("cluster_name", help="Cluster name (e.g. 'Lido x Obol: Ethereal Elf')")
    parser.add_argument("--network", default="mainnet", help="Network (default: mainnet)")
    parser.add_argument("--hours", type=int, default=24, help="Hours to look back (default: 24)")
    parser.add_argument("--slot", type=int, default=None, help="Analyze a specific slot")
    parser.add_argument("--limit", type=int, default=5000, help="Max log entries per query (default: 5000)")
    args = parser.parse_args()

    headers = get_auth_header()
    if not headers:
        print(json.dumps({"error": "OBOL_GRAFANA_API_TOKEN environment variable is not set"}))
        sys.exit(1)

    prom_url, loki_url = discover_datasources(headers)
    if not prom_url and not loki_url:
        print(json.dumps({"error": "Could not discover Prometheus or Loki datasources from Grafana"}))
        sys.exit(1)

    now_ts = int(datetime.now(tz=timezone.utc).timestamp())

    if args.slot is not None:
        # Specific slot analysis
        genesis = GENESIS_TIME.get(args.network)
        if not genesis:
            print(json.dumps({"error": f"Unknown genesis time for network '{args.network}'"}))
            sys.exit(1)

        slot_ts = genesis + args.slot * SECONDS_PER_SLOT
        slot_time = datetime.fromtimestamp(slot_ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        slot_events = []
        if loki_url:
            slot_events = query_slot_logs(loki_url, headers, args.cluster_name, args.network, args.slot, args.limit)

        output = {
            "mode": "slot_analysis",
            "cluster_name": args.cluster_name,
            "network": args.network,
            "slot": args.slot,
            "slot_time": slot_time,
            "epoch": args.slot // SLOTS_PER_EPOCH,
            "events": slot_events,
            "event_count": len(slot_events),
        }

        print(json.dumps(output, indent=2))
        return

    # Time range analysis
    start_ts = now_ts - args.hours * 3600
    start_ns = start_ts * 1_000_000_000
    end_ns = now_ts * 1_000_000_000

    print(f"Querying timeouts for cluster '{args.cluster_name}' on {args.network} over last {args.hours}h...", file=sys.stderr)

    timeout_events = []
    round_changes = []
    decided_events = []
    bn_calls = []
    consensus_timeouts = []

    if loki_url:
        print("  Fetching compare timeout events...", file=sys.stderr)
        timeout_events = query_timeout_events(loki_url, headers, args.cluster_name, args.network, start_ns, end_ns, args.limit)
        print(f"  Found {len(timeout_events)} timeout events", file=sys.stderr)

        if timeout_events:
            # Only query correlated events if there are timeouts
            print("  Fetching round changes...", file=sys.stderr)
            round_changes = query_round_changes(loki_url, headers, args.cluster_name, args.network, start_ns, end_ns, args.limit)
            print(f"  Found {len(round_changes)} round changes", file=sys.stderr)

            print("  Fetching consensus decisions...", file=sys.stderr)
            decided_events = query_consensus_decided(loki_url, headers, args.cluster_name, args.network, start_ns, end_ns, args.limit)
            print(f"  Found {len(decided_events)} decisions", file=sys.stderr)

            print("  Fetching consensus timeouts...", file=sys.stderr)
            consensus_timeouts = query_consensus_timeouts(loki_url, headers, args.cluster_name, args.network, start_ns, end_ns, args.limit)
            print(f"  Found {len(consensus_timeouts)} full consensus timeouts", file=sys.stderr)

            print("  Fetching BN call logs...", file=sys.stderr)
            bn_calls = query_bn_call_logs(loki_url, headers, args.cluster_name, args.network, start_ns, end_ns, args.limit)
            print(f"  Found {len(bn_calls)} BN call events", file=sys.stderr)

    # Prometheus metrics
    prom_metrics = {}
    if prom_url:
        print("  Fetching Prometheus metrics...", file=sys.stderr)
        prom_metrics = query_prometheus_metrics(prom_url, headers, args.cluster_name, args.network, start_ts, now_ts)

    # Correlate events
    correlations = {}
    if timeout_events:
        print("  Correlating events...", file=sys.stderr)
        correlations = correlate_events(timeout_events, round_changes, decided_events, bn_calls, consensus_timeouts)

    # Build summary
    summary = build_summary(timeout_events, correlations, prom_metrics, args.network)

    output = {
        "mode": "time_range_analysis",
        "cluster_name": args.cluster_name,
        "network": args.network,
        "time_range": {
            "start": datetime.fromtimestamp(start_ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": datetime.fromtimestamp(now_ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "hours": args.hours,
        },
        "timeout_events": timeout_events,
        "correlations": correlations,
        "metrics": prom_metrics,
        "summary": summary,
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
