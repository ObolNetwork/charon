#!/usr/bin/env bash

while ! curl "http://${NODE}:3600/up" 2>/dev/null; do
  echo "Waiting for http://${NODE}:3600/up to become available..."
  sleep 5
done

echo "Creating testnet config"
rm -rf /tmp/testnet || true
mkdir /tmp/testnet/
curl "http://${NODE}:3600/eth/v1/config/spec" | jq -r .data | yq -P > /tmp/testnet/config.yaml
echo "0" > /tmp/testnet/deploy_block.txt

for f in /compose/"${NODE}"/validator_keys/keystore-*.json; do
  echo "Importing key ${f}"
  cat "$(echo "${f}" | sed 's/json/txt/')" | lighthouse account validator import \
    --testnet-dir "/tmp/testnet" \
    --stdin-inputs \
    --keystore "${f}"
done


echo "Starting lighthouse validator client for ${NODE}"
exec lighthouse validator \
  --testnet-dir "/tmp/testnet" \
  --beacon-nodes "http://${NODE}:3600" \
  --suggested-fee-recipient "0x0000000000000000000000000000000000000000"
