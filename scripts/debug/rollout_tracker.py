#!/usr/bin/env python3
"""
Track rollout progress of patched charon versions (v1.9.2, v1.8.3) across the fleet.

Usage:
  source .env && python3 scripts/debug/rollout_tracker.py [--output FILE]

Outputs a markdown report with:
- Overall progress (patched / total)
- Per-operator status sorted by validator count (most urgent first)
- Remaining operators to chase
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

GRAFANA_BASE = "https://grafana.monitoring.gcp.obol.tech"

# Versions considered "patched" — only rc6+ has the full fix (buffered loki + deadliner + compare removal)
PATCHED_VERSIONS = {
    "v1.9.2-rc6","v1.9.2", "v1.8.3",
}


def fetch_json(url, headers):
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return None


def pq(prom_url, headers, query):
    url = f"{prom_url}query?query={urllib.parse.quote(query)}"
    r = fetch_json(url, headers)
    return r.get("data", {}).get("result", []) if r else []


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Track patch rollout progress")
    parser.add_argument("--output", default="docs/rollout_progress.md", help="Output file")
    args = parser.parse_args()

    token = os.environ.get("OBOL_GRAFANA_API_TOKEN")
    if not token:
        print("OBOL_GRAFANA_API_TOKEN not set", file=sys.stderr)
        sys.exit(1)
    headers = {"Authorization": f"Bearer {token}"}

    # Discover prometheus
    ds = fetch_json(f"{GRAFANA_BASE}/api/datasources", headers)
    prom_url = None
    for d in ds or []:
        if d.get("type") == "prometheus" and d.get("name") == "prometheus":
            prom_url = f"{GRAFANA_BASE}/api/datasources/proxy/{d['id']}/api/v1/"
    if not prom_url:
        print("Could not find prometheus", file=sys.stderr)
        sys.exit(1)

    print("Collecting fleet data...", file=sys.stderr)

    # Discover Loki peers
    loki_url = None
    for d in ds or []:
        if d.get("type") == "loki" and d.get("name") == "Loki":
            loki_url = f"{GRAFANA_BASE}/api/datasources/proxy/{d['id']}/loki/api/v1/"

    loki_peers = set()
    if loki_url:
        print("  Finding peers sending logs...", file=sys.stderr)
        import time as time_mod
        now = int(time_mod.time())
        params = urllib.parse.urlencode({
            "match[]": '{cluster_network="mainnet"}',
            "start": str((now - 3600) * 1_000_000_000),
            "end": str(now * 1_000_000_000),
        })
        r = fetch_json(f"{loki_url}series?{params}", headers)
        if r:
            for s in r.get("data", []):
                cn = s.get("cluster_name", "")
                peer = s.get("cluster_peer", "")
                if cn and peer:
                    loki_peers.add((cn, peer))
        print(f"  Found {len(loki_peers)} peers sending logs", file=sys.stderr)

    # Versions (only for peers sending logs)
    versions = {}
    for d in pq(prom_url, headers, 'app_version{cluster_network="mainnet"}'):
        key = (d["metric"].get("cluster_name", ""), d["metric"].get("cluster_peer", ""))
        if loki_peers and key not in loki_peers:
            continue
        versions[key] = {
            "version": d["metric"].get("version", "?"),
            "nickname": d["metric"].get("nickname", ""),
        }

    # Validator counts
    validators = {}
    for d in pq(prom_url, headers, 'core_scheduler_validators_active{cluster_network="mainnet"}'):
        cn = d["metric"].get("cluster_name", "")
        try:
            validators[cn] = max(validators.get(cn, 0), int(float(d["value"][1])))
        except:
            pass

    # Attester failure rates
    timeouts = {}
    for d in pq(prom_url, headers,
                'sum(rate(core_consensus_timeout_total{cluster_network="mainnet",duty="attester"}[1h])) by (cluster_name, cluster_peer) * 3600'):
        key = (d["metric"].get("cluster_name", ""), d["metric"].get("cluster_peer", ""))
        timeouts[key] = float(d["value"][1])

    decisions = {}
    for d in pq(prom_url, headers,
                'sum(rate(core_consensus_duration_seconds_count{cluster_network="mainnet",duty="attester"}[1h])) by (cluster_name, cluster_peer) * 3600'):
        key = (d["metric"].get("cluster_name", ""), d["metric"].get("cluster_peer", ""))
        decisions[key] = float(d["value"][1])

    # Build node list
    nodes = []
    for key, info in versions.items():
        cn, peer = key
        ver = info["version"]
        nick = info["nickname"]
        patched = any(ver.startswith(p.rstrip("0123456789-rc")) or ver in PATCHED_VERSIONS for p in PATCHED_VERSIONS)
        # Simpler: just check membership
        patched = ver in PATCHED_VERSIONS
        to = timeouts.get(key, 0)
        dec = decisions.get(key, 0)
        total = to + dec
        fail = (to / total * 100) if total > 0 else 0
        vals = validators.get(cn, 0)

        nodes.append({
            "cluster": cn,
            "peer": peer,
            "nickname": nick,
            "version": ver,
            "patched": patched,
            "validators": vals,
            "fail_pct": fail,
            "timeouts_per_hour": to,
        })

    total_nodes = len(nodes)
    patched_nodes = sum(1 for n in nodes if n["patched"])
    unpatched_nodes = total_nodes - patched_nodes
    total_validators = sum(validators.values())

    # Validators at risk (in clusters with at least one unpatched node)
    clusters_with_unpatched = set()
    for n in nodes:
        if not n["patched"]:
            clusters_with_unpatched.add(n["cluster"])
    validators_at_risk = sum(validators.get(cn, 0) for cn in clusters_with_unpatched)

    # Group unpatched by operator (nickname)
    unpatched_operators = {}
    for n in nodes:
        if n["patched"]:
            continue
        nick = n["nickname"] or f'(no nickname: {n["peer"]})'
        unpatched_operators.setdefault(nick, {
            "nodes": [],
            "clusters_seen": set(),
            "total_validators": 0,
            "total_timeouts": 0,
        })
        op = unpatched_operators[nick]
        op["nodes"].append(n)
        # Sum validators per unique cluster (not per node, since all nodes in a cluster report the same count)
        if n["cluster"] not in op["clusters_seen"]:
            op["clusters_seen"].add(n["cluster"])
            op["total_validators"] += n["validators"]
        op["total_timeouts"] += n["timeouts_per_hour"]

    # Sort by validator count descending
    sorted_operators = sorted(unpatched_operators.items(),
                              key=lambda x: (-x[1]["total_validators"], -x[1]["total_timeouts"]))

    # Generate report
    now_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = []
    lines.append("# Patch Rollout Progress")
    lines.append("")
    lines.append(f"**Last updated:** {now_str}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Patched nodes | **{patched_nodes}** / {total_nodes} ({100*patched_nodes/total_nodes:.1f}%) |")
    lines.append(f"| Unpatched nodes | **{unpatched_nodes}** |")
    lines.append(f"| Validators at risk | **{validators_at_risk}** / {total_validators} |")
    lines.append(f"| Unpatched operators | **{len(sorted_operators)}** |")
    lines.append(f"| Target versions | {', '.join(sorted(v for v in PATCHED_VERSIONS if 'rc' not in v))} (+ release candidates) |")
    lines.append("")

    # Progress bar
    pct = 100 * patched_nodes / total_nodes if total_nodes else 0
    filled = int(pct / 2)
    bar = "█" * filled + "░" * (50 - filled)
    lines.append(f"```")
    lines.append(f"[{bar}] {pct:.1f}%")
    lines.append(f"```")
    lines.append("")

    # Patched nodes list (brief)
    lines.append("## Patched Nodes")
    lines.append("")
    patched_by_version = {}
    for n in nodes:
        if n["patched"]:
            patched_by_version.setdefault(n["version"], []).append(n)
    for ver in sorted(patched_by_version.keys()):
        pnodes = patched_by_version[ver]
        names = sorted(set(n["nickname"] or n["peer"] for n in pnodes))
        lines.append(f"- **{ver}**: {len(pnodes)} nodes — {', '.join(names[:10])}{'...' if len(names) > 10 else ''}")
    lines.append("")

    # Remaining operators to chase
    lines.append("## Remaining Operators (sorted by validator count, most urgent first)")
    lines.append("")

    for nick, op in sorted_operators:
        node_list = op["nodes"]
        clusters = sorted(set(n["cluster"] for n in node_list))
        versions_seen = sorted(set(n["version"] for n in node_list))
        max_fail = max(n["fail_pct"] for n in node_list)
        total_to = op["total_timeouts"]

        lines.append(f"- [ ] **{nick}** — {op['total_validators']} validators, {len(node_list)} node(s), on {', '.join(versions_seen)}")
        if total_to > 0:
            lines.append(f"  - Attester timeouts: {total_to:.0f}/h, worst fail rate: {max_fail:.1f}%")
        for cn in clusters:
            cn_nodes = [n for n in node_list if n["cluster"] == cn]
            peers = ", ".join(f"`{n['peer']}`" for n in cn_nodes)
            lines.append(f"  - {cn}: {peers}")
        lines.append("")

    output = "\n".join(lines)
    with open(args.output, "w") as f:
        f.write(output + "\n")

    print(f"Written to {args.output}", file=sys.stderr)
    print(f"Progress: {patched_nodes}/{total_nodes} ({pct:.1f}%) — {len(sorted_operators)} operators remaining", file=sys.stderr)


if __name__ == "__main__":
    main()
