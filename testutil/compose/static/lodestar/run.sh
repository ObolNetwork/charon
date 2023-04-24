#!/bin/sh

while ! curl "http://${NODE}:3600/up" 2>/dev/null; do
  echo "Waiting for http://${NODE}:3600/up to become available..."
  sleep 5
done

echo "Creating testnet config"
rm -rf /tmp/testnet || true
mkdir /tmp/testnet/
curl "http://${NODE}:3600/eth/v1/config/spec" | jq -r .data | yq -P > /tmp/testnet/config.yaml

for f in /compose/"${NODE}"/validator_keys/keystore-*.json; do
    echo "Importing key ${f}"

    # Import keystore with password.
    node /usr/app/packages/cli/bin/lodestar validator import \
        --network="dev" \
        --presetFile="/tmp/testnet/config.yaml" \
        --paramsFile="/tmp/testnet/config.yaml" \
        --importKeystores="$f" \
        --importKeystoresPassword="${f//json/txt}"
done

echo "Imported all keys"

node /usr/app/packages/cli/bin/lodestar validator \
    --network="dev" \
    --presetFile="/tmp/testnet/config.yaml" \
    --paramsFile="/tmp/testnet/config.yaml" \
    --metrics=true \
    --metrics.address="0.0.0.0" \
    --metrics.port=5064 \
    --beaconNodes="http://$NODE:3600" \
    --distributed
