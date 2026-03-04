#!/usr/bin/env python3
"""
Collects data for missed proposal analysis.
Requires OBOL_GRAFANA_API_TOKEN environment variable.
Usage: python missed_proposal.py <cluster_name> <slot> [network]
  cluster_name: e.g. "Lido x Obol: Ethereal Elf"
  slot: slot number (e.g. 13813408)
  network: mainnet (default), hoodi, sepolia, etc.

Outputs JSON with cluster config, consensus leaders, logs, and inclusion metrics.
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

# Network genesis timestamps (Unix seconds)
GENESIS_TIME = {
    "mainnet": 1606824023,
    "hoodi": 1742212800,
    "sepolia": 1655733600,
}

SLOTS_PER_EPOCH = 32
SECONDS_PER_SLOT = 12

# Proposer duty type value (from core/types.go)
DUTY_TYPE_PROPOSER = 1


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


def discover_datasources(headers: dict) -> tuple[str | None, str | None]:
    """Discover Prometheus and Loki datasource proxy URLs from Grafana."""
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
    """Query Prometheus with raw query."""
    url = f"{prom_url}query?query={urllib.parse.quote(query)}"
    return fetch_json(url, headers, silent=True)


def prom_query_at_time(prom_url: str, headers: dict, query: str, timestamp: int) -> dict | None:
    """Query Prometheus at a specific timestamp."""
    url = f"{prom_url}query?query={urllib.parse.quote(query)}&time={timestamp}"
    return fetch_json(url, headers, silent=True)


def prom_query_cluster(prom_url: str, headers: dict, metric: str, cluster_name: str, network: str) -> dict | None:
    """Query Prometheus for a metric with cluster labels."""
    query = f'{metric}{{cluster_name="{cluster_name}",cluster_network="{network}"}}'
    return prom_query(prom_url, headers, query)


def extract_metric_value(result: dict | None, metric: str = "") -> str:
    """Extract value from Prometheus query result."""
    if not result:
        return "NOT_FOUND"
    data = result.get("data", {}).get("result", [])
    if not data:
        return "NOT_FOUND"

    if metric == "app_version":
        versions = sorted(set(r.get("metric", {}).get("version", "?") for r in data))
        return ", ".join(versions) if versions else "NOT_FOUND"

    return data[0].get("value", [None, "NOT_FOUND"])[1]


def loki_query(loki_url: str, headers: dict, logql: str, start_ns: int, end_ns: int) -> dict | None:
    """Query Loki for logs."""
    params = urllib.parse.urlencode({
        "query": logql,
        "start": str(start_ns),
        "end": str(end_ns),
        "limit": "2000",
    })
    url = f"{loki_url}query_range?{params}"
    return fetch_json(url, headers, silent=True)


def get_cluster_config(prom_url: str, headers: dict, cluster_name: str, network: str) -> dict:
    """Fetch cluster configuration from Prometheus."""
    config = {
        "name": cluster_name,
        "network": network,
        "cluster_hash": "NOT_FOUND",
        "version": "NOT_FOUND",
        "operators": "NOT_FOUND",
        "threshold": "NOT_FOUND",
        "active_validators": "NOT_FOUND",
        "total_validators": "NOT_FOUND",
        "peers": [],
    }

    if not prom_url:
        return config

    # Query cluster-level metrics
    operators_raw = prom_query_cluster(prom_url, headers, "cluster_operators", cluster_name, network)
    config["operators"] = extract_metric_value(operators_raw)

    # Extract cluster_hash
    if operators_raw:
        data = operators_raw.get("data", {}).get("result", [])
        if data:
            config["cluster_hash"] = data[0].get("metric", {}).get("cluster_hash", "NOT_FOUND")

    config["version"] = extract_metric_value(
        prom_query_cluster(prom_url, headers, "app_version", cluster_name, network), "app_version"
    )
    config["threshold"] = extract_metric_value(
        prom_query_cluster(prom_url, headers, "cluster_threshold", cluster_name, network)
    )
    config["active_validators"] = extract_metric_value(
        prom_query_cluster(prom_url, headers, "core_scheduler_validators_active", cluster_name, network)
    )
    config["total_validators"] = extract_metric_value(
        prom_query_cluster(prom_url, headers, "cluster_validators", cluster_name, network)
    )

    # Query per-peer info
    idx_raw = prom_query_cluster(prom_url, headers, "app_peerinfo_index", cluster_name, network)
    nick_raw = prom_query_cluster(prom_url, headers, "app_peerinfo_nickname", cluster_name, network)
    ver_raw = prom_query_cluster(prom_url, headers, "app_peerinfo_version", cluster_name, network)

    # Build lookup maps
    nick_map = {}
    if nick_raw:
        for r in nick_raw.get("data", {}).get("result", []):
            peer = r.get("metric", {}).get("peer")
            if peer:
                nick_map[peer] = r.get("metric", {}).get("peer_nickname", "?")

    ver_map = {}
    if ver_raw:
        for r in ver_raw.get("data", {}).get("result", []):
            peer = r.get("metric", {}).get("peer")
            if peer:
                ver_map[peer] = r.get("metric", {}).get("version", "?")

    # Build peer list
    peers = []
    seen_peers = set()
    if idx_raw:
        for r in idx_raw.get("data", {}).get("result", []):
            peer = r.get("metric", {}).get("peer")
            index = int(r.get("value", [None, 0])[1])
            if peer and peer not in seen_peers:
                seen_peers.add(peer)
                peers.append({
                    "index": index,
                    "peer": peer,
                    "nickname": nick_map.get(peer, "?"),
                    "version": ver_map.get(peer, "?"),
                })

    peers.sort(key=lambda x: x["index"])
    config["peers"] = peers

    return config


def calculate_leaders(slot: int, num_nodes: int, peers: list[dict]) -> list[dict]:
    """Calculate consensus leaders for rounds 1, 2, 3."""
    leaders = []
    for round_num in range(1, 4):
        leader_index = (slot + DUTY_TYPE_PROPOSER + round_num) % num_nodes
        peer_name = "unknown"
        for p in peers:
            if p["index"] == leader_index:
                peer_name = p["peer"]
                break
        leaders.append({
            "round": round_num,
            "index": leader_index,
            "peer": peer_name,
        })
    return leaders


def extract_logfmt(line: str, field: str) -> str:
    """Extract a field value from a logfmt-formatted line."""
    # Try quoted value first
    m = re.search(rf'{field}="([^"]*)"', line)
    if m:
        return m.group(1)
    # Try unquoted value
    m = re.search(rf"{field}=(\S+)", line)
    if m:
        return m.group(1)
    return ""


def parse_logs(logs_raw: dict | None, slot: int, slot_timestamp: int) -> dict:
    """Parse Loki logs and extract relevant events."""
    result = {
        "total_entries": 0,
        "peers_with_logs": [],
        "events": [],
        "warnings": [],
    }

    if not logs_raw:
        result["warnings"].append("No logs returned from Loki")
        return result

    streams = logs_raw.get("data", {}).get("result", [])
    if not streams:
        result["warnings"].append("No log streams found for this slot/duty")
        return result

    slot_timestamp_ns = slot_timestamp * 1_000_000_000

    # Collect all entries
    entries = []
    peers_seen = set()
    for stream in streams:
        peer = stream.get("stream", {}).get("cluster_peer", "unknown")
        peers_seen.add(peer)
        for ts_str, line in stream.get("values", []):
            entries.append((int(ts_str), peer, line))

    result["peers_with_logs"] = sorted(peers_seen)
    result["total_entries"] = len(entries)
    entries.sort(key=lambda x: x[0])

    # Parse events
    seen_first = set()
    events = []

    for ts_ns, peer, line in entries:
        msg = extract_logfmt(line, "msg")
        level = extract_logfmt(line, "level")
        if not msg:
            continue

        offset_ms = (ts_ns - slot_timestamp_ns) / 1_000_000
        offset_s = offset_ms / 1000

        event = {
            "offset_s": round(offset_s, 3),
            "peer": peer,
            "type": "",
            "details": {},
        }

        # --- SCHEDULER ---
        if msg == "Slot ticked":
            if "slot_ticked" not in seen_first:
                seen_first.add("slot_ticked")
                event["type"] = "slot_ticked"
                events.append(event)

        elif msg == "Resolved proposer duty":
            pubkey = extract_logfmt(line, "pubkey")
            vidx = extract_logfmt(line, "vidx")
            key = f"resolved:{pubkey}"
            if key not in seen_first:
                seen_first.add(key)
                event["type"] = "resolved_duty"
                event["details"] = {"pubkey": pubkey, "vidx": vidx}
                events.append(event)

        # --- FETCHER ---
        elif msg == "Calling beacon node endpoint...":
            endpoint = extract_logfmt(line, "endpoint")
            event["type"] = "bn_call_start"
            event["details"] = {"endpoint": endpoint}
            events.append(event)

        elif msg == "Beacon node call finished":
            endpoint = extract_logfmt(line, "endpoint")
            rtt = extract_logfmt(line, "rtt")
            event["type"] = "bn_call_done"
            event["details"] = {"endpoint": endpoint, "rtt": rtt}
            events.append(event)

        elif msg == "Beacon node call took longer than expected":
            endpoint = extract_logfmt(line, "endpoint")
            rtt = extract_logfmt(line, "rtt")
            event["type"] = "bn_call_slow"
            event["details"] = {"endpoint": endpoint, "rtt": rtt}
            events.append(event)

        # --- CONSENSUS ---
        elif msg == "QBFT consensus instance starting":
            if "consensus_started" not in seen_first:
                seen_first.add("consensus_started")
                event["type"] = "consensus_started"
                events.append(event)

        elif msg == "QBFT round changed":
            old_round = extract_logfmt(line, "round")
            new_round = extract_logfmt(line, "new_round")
            reason = extract_logfmt(line, "timeout_reason")
            key = f"round_change:{old_round}"
            if key not in seen_first:
                seen_first.add(key)
                event["type"] = "round_timeout"
                event["details"] = {"old_round": old_round, "new_round": new_round, "reason": reason}
                events.append(event)

        elif msg == "QBFT consensus decided":
            if "consensus_decided" not in seen_first:
                seen_first.add("consensus_decided")
                event["type"] = "consensus_decided"
                event["details"] = {
                    "round": extract_logfmt(line, "round"),
                    "leader_name": extract_logfmt(line, "leader_name"),
                    "leader_index": extract_logfmt(line, "leader_index"),
                }
                events.append(event)

        # --- VALIDATOR API ---
        elif msg == "Beacon block proposal received from validator client":
            block_version = extract_logfmt(line, "block_version")
            event["type"] = "block_proposal_received"
            event["details"] = {"block_version": block_version, "blinded": False}
            events.append(event)

        elif msg == "Blinded beacon block received from validator client":
            block_version = extract_logfmt(line, "block_version")
            event["type"] = "block_proposal_received"
            event["details"] = {"block_version": block_version, "blinded": True}
            events.append(event)

        # --- SIG AGGREGATION ---
        elif msg == "Successfully aggregated partial signatures to reach threshold":
            vapi_endpoint = extract_logfmt(line, "vapi_endpoint")
            event["type"] = "threshold_reached"
            event["details"] = {"vapi_endpoint": vapi_endpoint}
            events.append(event)

        # --- BROADCAST ---
        elif msg in ("Successfully submitted proposal to beacon node",
                     "Successfully submitted block proposal to beacon node"):
            delay = extract_logfmt(line, "delay")
            event["type"] = "broadcast_success"
            event["details"] = {"delay": delay}
            events.append(event)

        elif msg == "Timeout calling bcast/broadcast, duty expired":
            vapi_endpoint = extract_logfmt(line, "vapi_endpoint")
            event["type"] = "broadcast_timeout"
            event["details"] = {"vapi_endpoint": vapi_endpoint}
            events.append(event)

        # --- SSE EVENTS ---
        elif msg == "Beacon node received block_gossip event too late":
            delay = extract_logfmt(line, "gossip_delay") or extract_logfmt(line, "delay")
            event["type"] = "sse_block_gossip_late"
            event["details"] = {"delay": delay}
            events.append(event)

        elif msg == "Beacon node received block event too late":
            delay = extract_logfmt(line, "block_delay") or extract_logfmt(line, "delay")
            event["type"] = "sse_block_late"
            event["details"] = {"delay": delay}
            events.append(event)

        # --- TRACKER ---
        elif msg == "All peers participated in duty":
            if "tracker_all" not in seen_first:
                seen_first.add("tracker_all")
                event["type"] = "tracker_all_participated"
                events.append(event)

        elif msg == "Not all peers participated in duty":
            if "tracker_partial" not in seen_first:
                seen_first.add("tracker_partial")
                absent = extract_logfmt(line, "absent")
                event["type"] = "tracker_partial_participation"
                event["details"] = {"absent": absent}
                events.append(event)

        elif msg in ("Broadcasted block included on-chain", "Broadcasted blinded block included on-chain"):
            if "tracker_included" not in seen_first:
                seen_first.add("tracker_included")
                pubkey = extract_logfmt(line, "pubkey")
                broadcast_delay = extract_logfmt(line, "broadcast_delay")
                event["type"] = "tracker_block_included"
                event["details"] = {
                    "pubkey": pubkey,
                    "broadcast_delay": broadcast_delay,
                    "blinded": "blinded" in msg,
                }
                events.append(event)

        elif msg in ("Broadcasted block never included on-chain", "Broadcasted blinded block never included on-chain"):
            if "tracker_missed" not in seen_first:
                seen_first.add("tracker_missed")
                pubkey = extract_logfmt(line, "pubkey")
                broadcast_delay = extract_logfmt(line, "broadcast_delay")
                event["type"] = "tracker_block_missed"
                event["details"] = {
                    "pubkey": pubkey,
                    "broadcast_delay": broadcast_delay,
                    "blinded": "blinded" in msg,
                }
                events.append(event)

        # --- ERRORS ---
        elif level == "error" and ("consensus timeout" in msg.lower() or "permanent failure" in msg.lower()):
            event["type"] = "error"
            event["details"] = {"message": msg}
            events.append(event)

    result["events"] = events
    return result


def check_inclusion_metric(prom_url: str, headers: dict, cluster_name: str, network: str, slot_timestamp: int) -> str:
    """Check inclusion metric delta to determine if block was missed."""
    if not prom_url:
        return "unknown"

    # InclCheckLag=6 slots, InclMissedLag=32 slots (from core/tracker/inclusion.go)
    incl_check_lag = 6
    incl_missed_lag = 32

    before_time = slot_timestamp + incl_check_lag * SECONDS_PER_SLOT - 1
    after_time = slot_timestamp + (incl_missed_lag + 2) * SECONDS_PER_SLOT

    metric_query = f'sum(core_tracker_inclusion_missed_total{{cluster_name="{cluster_name}",cluster_network="{network}",duty="proposer"}})'

    before_result = prom_query_at_time(prom_url, headers, metric_query, before_time)
    after_result = prom_query_at_time(prom_url, headers, metric_query, after_time)

    val_before = extract_metric_value(before_result)
    val_after = extract_metric_value(after_result)

    try:
        before_val = float(val_before) if val_before != "NOT_FOUND" else 0
        after_val = float(val_after) if val_after != "NOT_FOUND" else 0
        delta = after_val - before_val
        if delta > 0:
            return "missed"
        if val_after != "NOT_FOUND" or val_before != "NOT_FOUND":
            return "not_missed"
    except (ValueError, TypeError):
        pass

    return "unknown"


def main():
    if len(sys.argv) < 3:
        print(json.dumps({
            "error": "cluster name and slot are required",
            "usage": "python missed_proposal.py <cluster_name> <slot> [network]",
        }))
        sys.exit(1)

    cluster_name = sys.argv[1]
    try:
        slot = int(sys.argv[2])
    except ValueError:
        print(json.dumps({"error": f"invalid slot number: {sys.argv[2]}"}))
        sys.exit(1)

    network = sys.argv[3] if len(sys.argv) > 3 else "mainnet"

    # Check for auth token
    headers = get_auth_header()
    if not headers:
        print(json.dumps({"error": "OBOL_GRAFANA_API_TOKEN environment variable is not set"}))
        sys.exit(1)

    # Discover datasources
    prom_url, loki_url = discover_datasources(headers)
    if not prom_url and not loki_url:
        print(json.dumps({"error": "Could not discover Prometheus or Loki datasources from Grafana"}))
        sys.exit(1)

    # Calculate slot timing
    genesis = GENESIS_TIME.get(network)
    slot_timestamp = None
    slot_time = None
    epoch = slot // SLOTS_PER_EPOCH
    slot_in_epoch = slot % SLOTS_PER_EPOCH

    if genesis:
        slot_timestamp = genesis + slot * SECONDS_PER_SLOT
        slot_time = datetime.fromtimestamp(slot_timestamp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Collect cluster config
    cluster_config = get_cluster_config(prom_url, headers, cluster_name, network)

    # Check if cluster was found
    cluster_found = not all(
        v in (None, "", "NOT_FOUND")
        for v in [cluster_config["version"], cluster_config["operators"], cluster_config["threshold"]]
    )

    # Calculate leaders
    leaders = []
    num_nodes = 0
    if cluster_found:
        try:
            num_nodes = int(cluster_config["operators"])
        except (ValueError, TypeError):
            num_nodes = len(cluster_config["peers"])

        if num_nodes > 0:
            leaders = calculate_leaders(slot, num_nodes, cluster_config["peers"])

    # Query logs from Loki
    logs_data = {"total_entries": 0, "peers_with_logs": [], "events": [], "warnings": []}
    if loki_url and slot_timestamp:
        # Time window: 15 seconds before slot to ~8 minutes after (for tracker)
        start_ns = (slot_timestamp - 15) * 1_000_000_000
        end_ns = (slot_timestamp + 500) * 1_000_000_000

        # Query pattern for proposer duty
        duty_pattern = f"{slot}/proposer"
        logql = f'{{cluster_name="{cluster_name}",cluster_network="{network}"}} |~ `{duty_pattern}|duty=proposer.*slot={slot}|slot.*{slot}.*proposer|block_slot={slot}`'

        logs_raw = loki_query(loki_url, headers, logql, start_ns, end_ns)
        logs_data = parse_logs(logs_raw, slot, slot_timestamp)
    elif not loki_url:
        logs_data["warnings"].append("Loki datasource not available")
    elif not slot_timestamp:
        logs_data["warnings"].append(f"Unknown genesis time for network '{network}'")

    # Check inclusion metric
    inclusion_status = "unknown"
    if prom_url and slot_timestamp:
        inclusion_status = check_inclusion_metric(prom_url, headers, cluster_name, network, slot_timestamp)

    # Check for missing peer logs
    if cluster_found and logs_data["peers_with_logs"]:
        expected_peers = {p["peer"] for p in cluster_config["peers"]}
        actual_peers = set(logs_data["peers_with_logs"])
        missing_peers = expected_peers - actual_peers
        if missing_peers:
            logs_data["warnings"].append(f"Missing logs from peers: {', '.join(sorted(missing_peers))}")

    # Build output
    output = {
        "slot": {
            "number": slot,
            "epoch": epoch,
            "slot_in_epoch": slot_in_epoch,
            "timestamp": slot_timestamp,
            "time": slot_time,
        },
        "duty": "proposer",
        "network": network,
        "cluster": cluster_config,
        "cluster_found": cluster_found,
        "leaders": leaders,
        "logs": logs_data,
        "inclusion_metric": inclusion_status,
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
