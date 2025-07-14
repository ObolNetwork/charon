#!/bin/bash

set -euo pipefail

#
# This script merges cluster-lock and key files from a source cluster (node)
# into a destination cluster (node).
# Please make backups before running this script.
# Please read the README.md instructions carefully.
#

# --- Configuration ---
CLUSTER_LOCK_FILENAME="cluster-lock.json"
VALIDATOR_KEYS_DIRNAME="validator_keys"

# --- Function to display script usage ---
function usage() {
    echo "Usage: $0 dst_cluster_folder src_cluster_folder"
    echo ""
    echo "  dst_cluster_folder: Path to the destination cluster's top-level folder"
    echo "                      (e.g., .charon/cluster1/node0)"
    echo "  src_cluster_folder: Path to the source cluster's top-level folder"
    echo "                      (e.g., .charon/cluster2/node0)"
    exit 1
}

# Check for correct number of arguments
if [ "$#" -ne 2 ]; then
    usage
fi

DST_ROOT_FOLDER="$1"
SRC_ROOT_FOLDER="$2"

DST_CLUSTER_LOCK_FILE="$DST_ROOT_FOLDER/$CLUSTER_LOCK_FILENAME"
SRC_CLUSTER_LOCK_FILE="$SRC_ROOT_FOLDER/$CLUSTER_LOCK_FILENAME"

DST_KEYS_FOLDER="$DST_ROOT_FOLDER/$VALIDATOR_KEYS_DIRNAME"
SRC_KEYS_FOLDER="$SRC_ROOT_FOLDER/$VALIDATOR_KEYS_DIRNAME"

# --- Part 1: Merge cluster-lock.json ---

# Check if required JSON files exist
if [ ! -f "$DST_CLUSTER_LOCK_FILE" ]; then
    echo "Error: Destination file '$DST_CLUSTER_LOCK_FILE' not found."
    exit 1
fi
if [ ! -f "$SRC_CLUSTER_LOCK_FILE" ]; then
    echo "Error: Source file '$SRC_CLUSTER_LOCK_FILE' not found."
    exit 1
fi

# Check file permissions for cluster-lock.json
if [ ! -r "$SRC_CLUSTER_LOCK_FILE" ]; then
    echo "Error: Source file '$SRC_CLUSTER_LOCK_FILE' is not readable. Please check permissions."
    exit 1
fi
if [ ! -r "$DST_CLUSTER_LOCK_FILE" ]; then
    echo "Error: Destination file '$DST_CLUSTER_LOCK_FILE' is not readable. Please check permissions."
    exit 1
fi
if [ ! -w "$DST_CLUSTER_LOCK_FILE" ]; then
    echo "Error: Destination file '$DST_CLUSTER_LOCK_FILE' is not writable. Please check permissions."
    exit 1
fi

# Check if jq is installed
if ! command -v jq &>/dev/null; then
    echo "Error: 'jq' is not installed. Please install it to use this script."
    echo "  On Debian/Ubuntu: sudo apt-get install jq"
    echo "  On macOS (Homebrew): brew install jq"
    exit 1
fi

echo "Merging '$CLUSTER_LOCK_FILENAME' from '$SRC_CLUSTER_LOCK_FILE' into '$DST_CLUSTER_LOCK_FILE'..."

# Use jq to perform the merge
# We will stream the destination JSON into jq's stdin, and load the source JSON
# as a separate argument using --slurpfile.
# Since --slurpfile reads the file into an array, we'll access the first element ([0])
# of the $src_data variable.
MERGED_JSON=$(
    jq \
        --slurpfile src_data "$SRC_CLUSTER_LOCK_FILE" \
        '
    .cluster_definition.num_validators = (.cluster_definition.num_validators + ($src_data[0].cluster_definition.num_validators)) |
    .cluster_definition.validators = (.cluster_definition.validators + $src_data[0].cluster_definition.validators) |
    .distributed_validators = (.distributed_validators + $src_data[0].distributed_validators)
    ' "$DST_CLUSTER_LOCK_FILE"
)

# Check if jq command was successful
if [ $? -ne 0 ]; then
    echo "Error: jq failed to process JSON files for cluster-lock. This might be due to incorrect JSON format or other jq issues."
    exit 1
fi

# Write the merged JSON back to the destination file
# It's safer to write to a temporary file first and then move it,
# to prevent data loss if the write operation is interrupted.
TEMP_DST_JSON_FILE=$(mktemp "${DST_CLUSTER_LOCK_FILE}.tmp.XXXXXX")
echo "$MERGED_JSON" >"$TEMP_DST_JSON_FILE"

# Check if the temporary file was written successfully
if [ $? -ne 0 ]; then
    echo "Error: Failed to write to temporary file '$TEMP_DST_JSON_FILE'."
    rm -f "$TEMP_DST_JSON_FILE" # Clean up temp file
    exit 1
fi

# Move the temporary file to overwrite the original destination file
mv "$TEMP_DST_JSON_FILE" "$DST_CLUSTER_LOCK_FILE"

# Check if mv command was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to move temporary file to '$DST_CLUSTER_LOCK_FILE'. Original file might be intact."
    exit 1
fi

# Get the count of validators from the source file for the summary message
SRC_VALIDATOR_COUNT_CLUSTER_LOCK=$(jq '.cluster_definition.num_validators' "$SRC_CLUSTER_LOCK_FILE")

echo "---"
echo "Merged $SRC_VALIDATOR_COUNT_CLUSTER_LOCK validators from '$SRC_CLUSTER_LOCK_FILE' into '$DST_CLUSTER_LOCK_FILE'."
echo "---"

# --- Part 2: Merge validator_keys folder ---

# Check if source validator_keys folder exists
if [ ! -d "$SRC_KEYS_FOLDER" ]; then
    echo "Error: Source folder '$SRC_KEYS_FOLDER' not found."
    echo "Skipping validator_keys merge as source folder does not exist."
else
    # Create destination validator_keys folder if it doesn't exist
    mkdir -p "$DST_KEYS_FOLDER"

    # Find the next available key index in the destination folder
    LAST_INDEX_DST=-1
    if compgen -G "${DST_KEYS_FOLDER}/keystore-*.json" >/dev/null; then
        for file in "$DST_KEYS_FOLDER"/keystore-*.json; do
            filename=$(basename "$file")
            # Extract the number after "keystore-" and before ".json"
            if [[ "$filename" =~ keystore-([0-9]+)\.json ]]; then
                current_index="${BASH_REMATCH[1]}"
                if ((current_index > LAST_INDEX_DST)); then
                    LAST_INDEX_DST="$current_index"
                fi
            fi
        done
    fi

    NEXT_INDEX=$((LAST_INDEX_DST + 1))
    MERGED_KEY_FILES_COUNT=0

    echo "Merging keys from '$SRC_KEYS_FOLDER' into '$DST_KEYS_FOLDER'..."

    # Process JSON files first to get the base index for each key
    # Then find and copy the corresponding TXT file with the same new index
    while IFS= read -r src_json_file; do
        if [ -f "$src_json_file" ]; then
            json_filename=$(basename "$src_json_file")

            # Extract the original index of the JSON file
            if [[ "$json_filename" =~ keystore-([0-9]+)\.json ]]; then
                original_index="${BASH_REMATCH[1]}"

                # Define the new filenames for both JSON and TXT
                new_json_filename="keystore-${NEXT_INDEX}.json"
                new_txt_filename="keystore-${NEXT_INDEX}.txt"

                # Check read permission for source JSON file
                if [ ! -r "$src_json_file" ]; then
                    echo "Error: Source JSON key file '$src_json_file' is not readable. Skipping."
                    continue # Skip to the next file
                fi

                # Copy the JSON file
                cp "$src_json_file" "$DST_KEYS_FOLDER/$new_json_filename"
                if [ $? -ne 0 ]; then
                    echo "Error: Failed to copy '$src_json_file' to '$DST_KEYS_FOLDER/$new_json_filename'. Skipping this key pair."
                    # Do not increment NEXT_INDEX or MERGED_KEY_FILES_COUNT as copy failed
                    continue
                fi
                echo "Copied '$json_filename' as '$new_json_filename'"

                # Check for and copy the corresponding TXT file
                src_txt_file="${SRC_KEYS_FOLDER}/keystore-${original_index}.txt"
                if [ -f "$src_txt_file" ]; then
                    if [ ! -r "$src_txt_file" ]; then
                        echo "Error: Corresponding TXT file '$src_txt_file' is not readable. Skipping TXT file for this key."
                    else
                        cp "$src_txt_file" "$DST_KEYS_FOLDER/$new_txt_filename"
                        if [ $? -ne 0 ]; then
                            echo "Error: Failed to copy '$src_txt_file' to '$DST_KEYS_FOLDER/$new_txt_filename'. This key might be partially merged."
                        else
                            echo "Copied 'keystore-${original_index}.txt' as '$new_txt_filename'"
                            MERGED_KEY_FILES_COUNT=$((MERGED_KEY_FILES_COUNT + 1)) # Increment count only if both files are processed successfully
                        fi
                    fi
                else
                    echo "Error: Corresponding TXT file 'keystore-${original_index}.txt' not found for '$json_filename'. Script will be terminated."
                    exit 1
                fi

                # Increment the index for the next *key pair*
                NEXT_INDEX=$((NEXT_INDEX + 1))
            else
                echo "Error: Could not parse index from '$json_filename'. Script will be terminated."
                exit 1
            fi
        fi
    done < <(find "$SRC_KEYS_FOLDER" -maxdepth 1 -name 'keystore-*.json' | sort -V)

    echo "---"
    echo "Merged $MERGED_KEY_FILES_COUNT keys from '$SRC_KEYS_FOLDER' to '$DST_KEYS_FOLDER'."
fi

echo ""
echo "WARNING: This script does not update the integrity hash of the merged cluster-lock.json file."
echo "         Please add CHARON_NO_VERIFY=true or --no-verify=true to 'charon run' command when starting your node."
echo "WARNING: Make sure to shutdown the other cluster before using the merged cluster-lock.json."
echo "         Failing to do so may result in slashing!"
echo ""
