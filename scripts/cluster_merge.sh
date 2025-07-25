#!/bin/bash

set -euo pipefail

#
# This script orchestrates the merging of multiple DV node configurations
# from a source cluster into a destination cluster. It calls node_merge.sh
# for each corresponding nodeX subfolder found.
# For single node merges, consider using node_merge.sh directly.
#
# Please make backups before running this script.
# Please read the README.md instructions carefully.
#

# --- Function to display script usage ---
function usage() {
    echo "Usage: $0 dst_cluster_folder src_cluster_folder"
    echo ""
    echo "  dst_cluster_folder: Path to the destination cluster folder"
    echo "                      (e.g., ~/dst_cluster)"
    echo "  src_cluster_folder: Path to the source cluster folder"
    echo "                      (e.g., ~/src_cluster)"
    exit 1
}

# --- Main script starts here ---

# Check for correct number of arguments
if [ "$#" -ne 2 ]; then
    usage
fi

DST_CLUSTER_ROOT="$1"
SRC_CLUSTER_ROOT="$2"

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
NODE_MERGE_SCRIPT="$SCRIPT_DIR/node_merge.sh"

# Check if node_merge.sh exists and is executable
if [ ! -f "$NODE_MERGE_SCRIPT" ]; then
    echo "Error: '$NODE_MERGE_SCRIPT' not found. Please ensure 'node_merge.sh' is in the same directory as 'cluster_merge.sh'."
    exit 1
fi
if [ ! -x "$NODE_MERGE_SCRIPT" ]; then
    echo "Error: '$NODE_MERGE_SCRIPT' is not executable. Please run 'chmod +x $NODE_MERGE_SCRIPT'."
    exit 1
fi

echo "--- Starting cluster merge from '$SRC_CLUSTER_ROOT' to '$DST_CLUSTER_ROOT' ---"
echo ""

# Find all nodeX folders in the source cluster
# Using find with -maxdepth 1 to only look in the immediate subdirectories
# and regex to match 'node' followed by one or more digits.
# Sorting numerically to ensure consistent processing order (node0, node1, node2, ..., node10)
NODE_FOLDERS=$(find "$SRC_CLUSTER_ROOT" -maxdepth 1 -type d -name 'node[0-9]*' | sort -V)

if [ -z "$NODE_FOLDERS" ]; then
    echo "No 'nodeX' subfolders found in the source cluster '$SRC_CLUSTER_ROOT'."
    echo "Cluster merge finished (nothing to merge)."
    exit 0
fi

for SRC_NODE_FOLDER_PATH in $NODE_FOLDERS; do
    NODE_NAME=$(basename "$SRC_NODE_FOLDER_PATH") # e.g., node0, node1
    DST_NODE_FOLDER_PATH="$DST_CLUSTER_ROOT/$NODE_NAME"

    echo "Attempting to merge node '$NODE_NAME':"
    echo "  Source: $SRC_NODE_FOLDER_PATH"
    echo "  Destination: $DST_NODE_FOLDER_PATH"
    echo ""

    # Check if the corresponding destination node folder exists
    if [ ! -d "$DST_NODE_FOLDER_PATH" ]; then
        echo "Error: Destination node folder '$DST_NODE_FOLDER_PATH' not found. Script will be terminated."
        exit 1
    fi

    # Call node_merge.sh for the current node pair
    "$NODE_MERGE_SCRIPT" "$DST_NODE_FOLDER_PATH" "$SRC_NODE_FOLDER_PATH"
    NODE_MERGE_EXIT_CODE=$?

    if [ $NODE_MERGE_EXIT_CODE -ne 0 ]; then
        echo "Error: node_merge.sh failed for '$NODE_NAME'. See above output for details."
        exit 1
    fi
    echo ""
done

echo "--- Cluster merge process complete ---"
