#!/usr/bin/env python3
"""
Build a comprehensive cluster registry from Grafana metrics for cohort analysis.

Outputs JSON with per-cluster and per-node metadata:
- Cluster: name, category, node count, validator count, threshold
- Per-node: charon version, BN client/version, BN peer count, feature flags,
  attestation_data latency, connection types, sends-to-loki, nickname/operator

Usage:
  source .env && python3 scripts/debug/cluster_registry.py [--network mainnet] [--time UNIX_TS]

Outputs cluster_registry.json to stdout.
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

GRAFANA_BASE = "https://grafana.monitoring.gcp.obol.tech"


def get_auth_header() -> dict:
    token = os.environ.get("OBOL_GRAFANA_API_TOKEN")
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def fetch_json(url: str, headers: dict) -> dict | None:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.HTTPError, urllib.error.URLError, Exception) as e:
        print(f"Error: {e}", file=sys.stderr)
        return None


def pq(prom_url: str, headers: dict, query: str, ts: int | None = None) -> list:
    params = {"query": query}
    if ts:
        params["time"] = str(ts)
    url = f"{prom_url}query?{urllib.parse.urlencode(params)}"
    r = fetch_json(url, headers)
    if not r:
        return []
    return r.get("data", {}).get("result", [])


def categorise_cluster(name: str, size: int) -> str:
    """Categorise cluster by operator type.

    Categories:
      etherfi_curated   - Professional operators running EtherFi validators (Curated, EtherFi:, Pier Two x Etherfi)
      etherfi_solo      - Solo/amateur EtherFi staker clusters (etherfi-obol-mainnet-eu-*, etherfi-obol-eu-*)
      lido_curated      - Professional operators running Lido validators (stakely, RockLogic, EBUNKER, empty-name Pier Two)
      lido_sdvt         - Lido Simple DVT clusters (7 amateur operators, "Lido x Obol: *")
      protocol_curated  - Other protocol curated clusters (StakeWise, Swell) with professional operators
      obol_internal     - Obol-operated clusters
      community         - Independent community clusters
      unknown           - Unidentified or single-node clusters
    """
    n = name.lower()

    # EtherFi curated: professional operators
    if "curated" in n and "etherfi" in n:
        return "etherfi_curated"
    if name.startswith("EtherFi:"):
        return "etherfi_curated"
    if name.startswith("Pier Two x Etherfi"):
        return "etherfi_curated"

    # EtherFi solo stakers
    if "etherfi" in n:
        return "etherfi_solo"

    # Lido curated: professional operators
    if "stakely" in n and ("lido" in n or "obol" in n):
        return "lido_curated"
    if "rocklogic" in n:
        return "lido_curated"
    if "ebunker" in n:
        return "lido_curated"
    if name == "?" and size == 4:
        # The unnamed Pier Two cluster
        return "lido_curated"
    # Lido Simple DVT: groups of amateur operators
    if "lido x obol" in n:
        return "lido_sdvt"

    # Other professional/protocol clusters
    if "stakewise" in n:
        return "protocol_curated"
    if "swell" in n:
        return "protocol_curated"

    # Obol internal
    if "obol" in n and ("mainnet" in n or "eigensquad" in n):
        return "obol_internal"
    if name == "Stakely Obol Portal":
        return "obol_internal"

    # Swell
    if "swell" in n:
        return "community"

    if name == "?" or size <= 1:
        return "unknown"

    return "community"


def parse_bn_client(version: str) -> str:
    if "Lighthouse" in version:
        return "Lighthouse"
    if "teku" in version.lower():
        return "Teku"
    if "Prysm" in version:
        return "Prysm"
    if "Nimbus" in version:
        return "Nimbus"
    if "Lodestar" in version:
        return "Lodestar"
    if "Grandine" in version:
        return "Grandine"
    return "unknown"


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Build cluster registry from Grafana metrics")
    parser.add_argument("--network", default="mainnet", help="Network (default: mainnet)")
    parser.add_argument("--time", type=int, default=None, help="Unix timestamp to query at (default: now)")
    args = parser.parse_args()

    headers = get_auth_header()
    if not headers:
        print(json.dumps({"error": "OBOL_GRAFANA_API_TOKEN not set"}))
        sys.exit(1)

    prom_url, _ = discover_datasources(headers)
    if not prom_url:
        print(json.dumps({"error": "Could not discover Prometheus datasource"}))
        sys.exit(1)

    net = args.network
    ts = args.time

    print("Collecting cluster registry...", file=sys.stderr)

    # 1. Cluster sizes
    print("  Cluster sizes...", file=sys.stderr)
    cluster_sizes = {}
    for d in pq(prom_url, headers, f'count(core_scheduler_current_slot{{cluster_network="{net}"}}) by (cluster_name, cluster_hash)', ts):
        cn = d["metric"].get("cluster_name", "?")
        ch = d["metric"].get("cluster_hash", "?")
        cluster_sizes[(cn, ch)] = int(float(d["value"][1]))

    # 2. Validator counts
    print("  Validator counts...", file=sys.stderr)
    validators = {}
    for d in pq(prom_url, headers, f'core_scheduler_validators_active{{cluster_network="{net}"}}', ts):
        key = (d["metric"].get("cluster_name", "?"), d["metric"].get("cluster_peer", "?"))
        try:
            validators[key] = int(float(d["value"][1]))
        except (ValueError, TypeError):
            pass

    # 3. Threshold
    print("  Thresholds...", file=sys.stderr)
    thresholds = {}
    for d in pq(prom_url, headers, f'cluster_threshold{{cluster_network="{net}"}}', ts):
        cn = d["metric"].get("cluster_name", "?")
        try:
            thresholds[cn] = int(float(d["value"][1]))
        except (ValueError, TypeError):
            pass

    # 4. Charon versions
    print("  Charon versions...", file=sys.stderr)
    charon_versions = {}
    for d in pq(prom_url, headers, f'app_version{{cluster_network="{net}"}}', ts):
        key = (d["metric"].get("cluster_name", "?"), d["metric"].get("cluster_peer", "?"))
        charon_versions[key] = {
            "version": d["metric"].get("version", "?"),
            "hostname": d["metric"].get("hostname", ""),
            "instance": d["metric"].get("instance", ""),
            "nickname": d["metric"].get("nickname", ""),
            "service_owner": d["metric"].get("service_owner", ""),
        }

    # 5. BN versions
    print("  BN versions...", file=sys.stderr)
    bn_versions = {}
    for d in pq(prom_url, headers, f'app_beacon_node_version{{cluster_network="{net}"}}', ts):
        key = (d["metric"].get("cluster_name", "?"), d["metric"].get("cluster_peer", "?"))
        bn_versions[key] = d["metric"].get("version", "?")

    # 6. BN peer counts
    print("  BN peer counts...", file=sys.stderr)
    bn_peers = {}
    for d in pq(prom_url, headers, f'app_beacon_node_peers{{cluster_network="{net}"}}', ts):
        key = (d["metric"].get("cluster_name", "?"), d["metric"].get("cluster_peer", "?"))
        try:
            bn_peers[key] = int(float(d["value"][1]))
        except (ValueError, TypeError):
            pass

    # 7. Feature flags
    print("  Feature flags...", file=sys.stderr)
    feature_flags = {}
    for d in pq(prom_url, headers, f'app_feature_flags{{cluster_network="{net}"}}', ts):
        key = (d["metric"].get("cluster_name", "?"), d["metric"].get("cluster_peer", "?"))
        ff = d["metric"].get("feature_flags", "")
        if ff:
            feature_flags.setdefault(key, []).append(ff)

    # 8. Attestation data latency p50
    print("  BN latency...", file=sys.stderr)
    att_latency = {}
    for d in pq(prom_url, headers,
                f'histogram_quantile(0.5, sum(rate(app_eth2_latency_seconds_bucket{{cluster_network="{net}",endpoint="attestation_data"}}[1h])) by (cluster_name, cluster_peer, le))',
                ts):
        key = (d["metric"].get("cluster_name", "?"), d["metric"].get("cluster_peer", "?"))
        try:
            att_latency[key] = round(float(d["value"][1]) * 1000, 1)
        except (ValueError, TypeError):
            pass

    # 9. Connection types
    print("  Connection types...", file=sys.stderr)
    conn_types = {}
    for d in pq(prom_url, headers, f'p2p_peer_connection_types{{cluster_network="{net}"}}', ts):
        key = (d["metric"].get("cluster_name", "?"), d["metric"].get("cluster_peer", "?"))
        typ = d["metric"].get("type", "?")
        proto = d["metric"].get("protocol", "?")
        try:
            val = float(d["value"][1])
        except (ValueError, TypeError):
            val = 0
        if val > 0:
            conn_types.setdefault(key, []).append({"type": typ, "protocol": proto})

    # 10. Peer indices
    print("  Peer indices...", file=sys.stderr)
    peer_indices = {}
    for d in pq(prom_url, headers, f'app_peerinfo_index{{cluster_network="{net}"}}', ts):
        key = (d["metric"].get("cluster_name", "?"), d["metric"].get("cluster_peer", "?"))
        try:
            peer_indices[key] = int(float(d["value"][1]))
        except (ValueError, TypeError):
            pass

    # 11. Attester timeout and decision rates
    print("  Attester performance...", file=sys.stderr)
    window = "1h"
    att_timeouts = {}
    for d in pq(prom_url, headers,
                f'sum(rate(core_consensus_timeout_total{{cluster_network="{net}",duty="attester"}}[{window}])) by (cluster_name, cluster_peer) * 3600',
                ts):
        key = (d["metric"].get("cluster_name", "?"), d["metric"].get("cluster_peer", "?"))
        att_timeouts[key] = round(float(d["value"][1]), 1)

    att_decisions = {}
    for d in pq(prom_url, headers,
                f'sum(rate(core_consensus_duration_seconds_count{{cluster_network="{net}",duty="attester"}}[{window}])) by (cluster_name, cluster_peer) * 3600',
                ts):
        key = (d["metric"].get("cluster_name", "?"), d["metric"].get("cluster_peer", "?"))
        att_decisions[key] = round(float(d["value"][1]), 1)

    # 12. Check Loki presence (which peers send logs) using /series endpoint
    print("  Loki presence...", file=sys.stderr)
    loki_peers = set()
    _, loki_url = discover_datasources(headers)
    if loki_url:
        import time as time_mod2
        now2 = ts or int(time_mod2.time())
        try:
            params = urllib.parse.urlencode({
                "match[]": f'{{cluster_network="{net}"}}',
                "start": str((now2 - 3600) * 1_000_000_000),
                "end": str(now2 * 1_000_000_000),
            })
            r = fetch_json(f"{loki_url}series?{params}", headers)
            if r:
                for s in r.get("data", []):
                    cn = s.get("cluster_name", "")
                    peer = s.get("cluster_peer", "")
                    if cn and peer:
                        loki_peers.add((cn, peer))
        except Exception:
            pass
    print(f"    Found {len(loki_peers)} peers sending logs to Loki", file=sys.stderr)

    # Build output
    print("  Building registry...", file=sys.stderr)
    registry = {"clusters": {}, "meta": {}}

    import time as time_mod
    registry["meta"] = {
        "generated_at": datetime.fromtimestamp(ts or time_mod.time(), tz=timezone.utc).isoformat(),
        "network": net,
        "query_time": ts,
        "total_clusters": len(cluster_sizes),
    }

    all_node_keys = set()
    for key in charon_versions:
        all_node_keys.add(key)

    for (cn, ch), size in cluster_sizes.items():
        category = categorise_cluster(cn, size)
        cluster_validators = set()
        nodes = []

        for key in all_node_keys:
            if key[0] != cn:
                continue
            peer = key[1]
            info = charon_versions.get(key, {})
            bn_ver = bn_versions.get(key, "unknown")
            to = att_timeouts.get(key, 0)
            dec = att_decisions.get(key, 0)
            total = to + dec
            fail_pct = round((to / total * 100), 2) if total > 0 else 0
            vals = validators.get(key)

            node = {
                "peer": peer,
                "index": peer_indices.get(key),
                "charon_version": info.get("version", "?"),
                "hostname": info.get("hostname", ""),
                "nickname": info.get("nickname", ""),
                "service_owner": info.get("service_owner", ""),
                "bn_client": parse_bn_client(bn_ver),
                "bn_version": bn_ver,
                "bn_peers": bn_peers.get(key),
                "feature_flags": sorted(feature_flags.get(key, [])),
                "attestation_data_latency_p50_ms": att_latency.get(key),
                "connection_types": conn_types.get(key, []),
                "sends_to_loki": key in loki_peers,
                "attester_timeouts_per_hour": to,
                "attester_decisions_per_hour": dec,
                "attester_fail_pct": fail_pct,
                "active_validators": vals,
            }
            nodes.append(node)

            if vals:
                cluster_validators.add(vals)

        cluster = {
            "name": cn,
            "hash": ch,
            "category": category,
            "node_count": size,
            "threshold": thresholds.get(cn),
            "active_validators": max(cluster_validators) if cluster_validators else None,
            "nodes": sorted(nodes, key=lambda n: n.get("index") or 999),
        }
        registry["clusters"][cn] = cluster

    # Summary stats
    cats = {}
    for c in registry["clusters"].values():
        cat = c["category"]
        cats.setdefault(cat, {"clusters": 0, "nodes": 0, "validators": 0})
        cats[cat]["clusters"] += 1
        cats[cat]["nodes"] += c["node_count"]
        if c["active_validators"]:
            cats[cat]["validators"] += c["active_validators"]
    registry["meta"]["categories"] = cats

    print(json.dumps(registry, indent=2))


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


if __name__ == "__main__":
    main()
