#!/usr/bin/env bash

# Generates the static.json file which is served as part of the beaconmock's static values provider.
# Note it should be a goerli testnet beacon node.

set -e

if [ -z "${BEACON_URL}" ]; then
  echo "BEACON_URL not set"
  exit 1
fi

echo "Using goerli testnet BEACON_URL=${BEACON_URL}"

ENDPOINTS=(\
 /eth/v1/beacon/genesis \
 /eth/v1/config/deposit_contract \
 /eth/v1/config/fork_schedule \
 /eth/v1/node/version \
 /eth/v1/config/spec\
 /eth/v2/beacon/blocks/0 \
)

FIRST=true
RESP="{"
for ENDPOINT in "${ENDPOINTS[@]}"; do
  if ${FIRST}; then
    FIRST=false
  else
    RESP="${RESP},"
  fi

  echo "Curling ${ENDPOINT}"
  VALUE=$(curl -s "${BEACON_URL}${ENDPOINT}")

  RESP="${RESP} \"${ENDPOINT}\": ${VALUE}"
done
RESP="${RESP} }"

TARGET="static.json"
echo "Writing ${TARGET}"
echo "${RESP}" | jq . > "${TARGET}"
