# Charon Scripts

## `cluster_merge.sh`

This script merges cluster definition (`cluster-lock.json`) and key files (`validator_keys` folder) from a source node folder into a destination node folder.
It helps expand an existing cluster with new validators given the same operators set and cluster configuration.

### Usage

```bash
./cluster_merge.sh <dst_cluster_folder> <src_cluster_folder>
```

- *<dst_cluster_folder>*: Path to the destination cluster node's top-level folder (e.g., `~/kurtosis-charon/.charon/cluster1/node0`).
- *<src_cluster_folder>*: Path to the source cluster node's top-level folder (e.g., `~/kurtosis-charon/.charon/cluster2/node0`).

The merge must be executed for all cluster nodes.

### What it Does

Merges `cluster-lock.json`:
- sums `num_validators`,
- concatenates `validators` and `distributed_validators` arrays.

Preserves other fields from the destination file.

Merges `validator_keys` folder :
- copies `keystore-N.json` and `keystore-N.txt` pairs from source to destination.
- renumber files sequentially (e.g., `keystore-0`, `keystore-1`, `keystore-10` are sorted numerically).

### Requirements

**bash** (standard on Linux/macOS) and **jq** (version 1.5+). 
Install via `sudo apt-get install jq` (Debian/Ubuntu) or `brew install jq` (macOS).

### Important Warnings

- Always back up your `cluster-lock.json` and `validator_keys` folders before use.
- Make sure the source and destination clusters have correct permissions and accessible by the script.
- The script does not update the integrity hash. You must use `CHARON_NO_VERIFY=true` or `--no-verify=true` with `charon run`.
- Shut down the source cluster before running the merged cluster.
    