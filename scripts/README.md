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

## Requirements

Both scripts require **bash** (standard on Linux/macOS) and **jq** (version 1.5+).
Install via `sudo apt-get install jq` (Debian/Ubuntu) or `brew install jq` (macOS).

## Important Warnings

- Always back up your `cluster-lock.json`, node folders, and `validator_keys` folders before use.
- Make sure the source and destination folders have correct permissions and are accessible by the script.
- The scripts do not update the integrity hash. You must use `CHARON_NO_VERIFY=true` or `--no-verify=true` with `charon run`.
- Shut down the source cluster or node before running the merged cluster.
