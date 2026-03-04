# Charon Scripts

This directory contains helper scripts for managing and merging Charon cluster and node configurations.

## `node_merge.sh`

This script merges node-level configuration and key files from a source node folder into a destination node folder.
It is useful for combining validator keys and configuration for single pair of nodes, ensuring all keys are present in the destination.

### Usage

```bash
./node_merge.sh <dst_node_folder> <src_node_folder>
```

- *<dst_node_folder>*: Path to the destination node's top-level folder (e.g., `cluster1/node0`).
- *<src_node_folder>*: Path to the source node's top-level folder (e.g., `cluster2/node0`).

The script will:
- Copy all `keystore-N.json` and `keystore-N.txt` pairs from the source to the destination.
- Renumber files sequentially in the destination folder, sorted numerically.
- Preserve other files in the destination folder.

## `cluster_merge.sh`

This script merges two clusters by running `node_merge.sh` for each `nodeX` subfolder found in the source cluster.
It helps expand an existing cluster with new validators, given the same operators set and cluster configuration.

### Usage

```bash
./cluster_merge.sh <dst_cluster_folder> <src_cluster_folder>
```

- *<dst_cluster_folder>*: Path to the destination cluster folder (e.g., `cluster1`).
- *<src_cluster_folder>*: Path to the source cluster folder (e.g., `cluster2`).

The script will execute `node_merge.sh` for each `nodeX` subfolder found in the source cluster.

## Monitoring and Diagnostics Scripts

The following scripts query Obol's Grafana/Prometheus/Loki observability stack and require the `OBOL_GRAFANA_API_TOKEN` environment variable to be set:

```bash
export OBOL_GRAFANA_API_TOKEN=<your-grafana-api-token>
```

### `grafana-datasources.sh`

Discovers Prometheus and Loki datasource proxy URLs from Grafana. Used internally by the other monitoring scripts.

#### Usage

```bash
./grafana-datasources.sh
```

Outputs two lines:
```
PROMETHEUS_URL=https://grafana.monitoring.gcp.obol.tech/api/datasources/proxy/<id>/api/v1/
LOKI_URL=https://grafana.monitoring.gcp.obol.tech/api/datasources/proxy/<id>/loki/api/v1/
```

### `cluster-config.sh`

Fetches cluster configuration metrics (version, operators, threshold, validators, and per-peer info) from Prometheus via Grafana proxy.

#### Usage

```bash
./cluster-config.sh <cluster_name> [network]
```

- *<cluster_name>*: Human-readable cluster name (e.g., `"Lido x Obol: Ethereal Elf"`).
- *[network]*: Network name — `mainnet` (default), `hoodi`, `sepolia`, etc.

#### Example

```bash
./cluster-config.sh "Lido x Obol: Ethereal Elf" mainnet
```

### `consensus-leader.sh`

Calculates the consensus leader sequence for a given slot and cluster using the QBFT leader election formula: `(slot + dutyType + round) % nodes`.

#### Usage

```bash
./consensus-leader.sh <cluster_name> <slot> [network] [duty_type]
```

- *<cluster_name>*: Human-readable cluster name.
- *<slot>*: Beacon chain slot number (e.g., `13813408`).
- *[network]*: Network name — `mainnet` (default), `hoodi`, `sepolia`, etc.
- *[duty_type]*: Duty type — `proposer` (default), `attester`, `randao`, etc.

#### Example

```bash
./consensus-leader.sh "Lido x Obol: Ethereal Elf" 13813408 mainnet proposer
```

### `duty-timeline.sh`

Generates a comprehensive chronological timeline of events for a specific duty across all peers, pulling logs from Loki and cluster metrics from Prometheus. Useful for post-mortem analysis of missed blocks or attestations.

#### Usage

```bash
./duty-timeline.sh <cluster_name> <slot> [network] [duty_type]
```

- *<cluster_name>*: Human-readable cluster name.
- *<slot>*: Beacon chain slot number (e.g., `13813408`).
- *[network]*: Network name — `mainnet` (default), `hoodi`, `sepolia`, etc.
- *[duty_type]*: Duty type — `proposer` (default), `attester`, `randao`, etc.

#### Example

```bash
./duty-timeline.sh "Lido x Obol: Ethereal Elf" 13813408 mainnet proposer
```

The script outputs duty info, expected consensus leaders, a chronological event timeline with offsets relative to slot start, and a summary covering consensus outcome, broadcast status, block inclusion, and peer participation.

## Requirements

All scripts require **bash** (standard on Linux/macOS) and **jq** (version 1.5+).
Install via `sudo apt-get install jq` (Debian/Ubuntu) or `brew install jq` (macOS).

The monitoring and diagnostics scripts additionally require **curl** and **bc**.

## Important Warnings

- Always back up your `cluster-lock.json`, node folders, and `validator_keys` folders before use.
- Make sure the source and destination folders have correct permissions and are accessible by the script.
- The scripts do not update the integrity hash. You must use `CHARON_NO_VERIFY=true` or `--no-verify=true` with `charon run`.
- Shut down the source cluster or node before running the merged cluster.
