---
name: cluster-config
description: Fetch cluster configuration metrics (version, operators, threshold, validators) from Prometheus
user-invokable: true
---

# Cluster Config

Fetch cluster configuration metrics from Prometheus for a given cluster name and optional network.

## Arguments

The user must provide:
- **cluster name** (required): e.g. `Lido x Obol: Ethereal Elf`
- **network** (optional, default: `mainnet`): e.g. `mainnet`, `hoodi`

## Execution

Run the script with the cluster name and network:
```bash
bash scripts/cluster-config.sh "<cluster_name>" "<network>"
```

## Output

Present the results to the user in a readable format:
- **Cluster**: name and network
- **App Version**: charon version running
- **Operators**: number of operators in the cluster
- **Threshold**: signature threshold
- **Active Validators**: currently active validators
- **Total Validators**: total validators in the cluster

If the script exits with an error (cluster not found), relay the error and suggest the user double-check the cluster name spelling or try a different network.
