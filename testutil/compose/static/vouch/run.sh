#!/usr/bin/env bash

# Running vouch VC is split into three steps:
# 1. Converting keys into a format which vouch understands. This is what ethdo does.
# 2. Creating configuration for vouch (vouch.yml).
# 3. Actually running the vouch validator client.

BASE_DIR="/tmp/vouch"
KEYS_DIR="/tmp/vouch/keys"
ACCOUNT_PASSPHRASE="secret" # Hardcoded ethdo account passphrase

rm -rf /tmp/vouch || true
mkdir ${BASE_DIR}
mkdir ${KEYS_DIR}

cp /compose/vouch/vouch.yml ${BASE_DIR}

# Create an ethdo wallet within the keys folder.
wallet="validators"
/app/ethdo --base-dir="${KEYS_DIR}" wallet create --wallet ${wallet}

# Import keys into the ethdo wallet.
account=0
for f in /compose/"${NODE}"/validator_keys/keystore-*.json; do
  accountName="account-${account}"
  echo "Importing key ${f} into ethdo wallet: ${wallet}/${accountName}"

  KEYSTORE_PASSPHRASE=$(cat "${f//json/txt}")
  /app/ethdo \
    --base-dir="${KEYS_DIR}" account import \
    --account="${wallet}"/"${accountName}" \
    --keystore="$f" \
    --passphrase="$ACCOUNT_PASSPHRASE" \
    --keystore-passphrase="$KEYSTORE_PASSPHRASE" \
    --allow-weak-passphrases

  # Increment account.
  # shellcheck disable=SC2003
  account=$(expr "$account" + 1)
done

# Log wallet info.
echo "Starting vouch validator client. Wallet info:"
/app/ethdo wallet info \
--wallet="${wallet}" \
--base-dir="${KEYS_DIR}" \
--verbose

# Now run vouch.
exec /app/vouch --base-dir=${BASE_DIR} --beacon-node-address="http://${NODE}:3600"
