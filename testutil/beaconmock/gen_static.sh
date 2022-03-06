#!/usr/bin/env bash

# Generates the static.json file which is served as part of the beaconmock's static values provider.

set -e

if [ -z "${BEACON_URL}" ]; then
  echo "BEACON_URL not set"
  exit 1
fi

echo "Using BEACON_URL=${BEACON_URL}"

TARGET="static.json"
ENDPOINTS=(/eth/v1/beacon/genesis /eth/v1/config/deposit_contract /eth/v1/config/fork_schedule /eth/v1/node/version /eth/v1/config/spec)

RESP="{"
FIRST=true
for ENDPOINT in "${ENDPOINTS[@]}"; do
  if [ "${FIRST}" == "true" ]; then
    FIRST=false
  else
      RESP="${RESP},"
  fi

  echo "Curling ${ENDPOINT}"
  VALUE=$(curl -s "${BEACON_URL}${ENDPOINT}")

  RESP="${RESP}\"${ENDPOINT}\":${VALUE}"
done

echo "Writing ${TARGET}"
RESP="${RESP}}"
echo "${RESP}" | jq . > "${TARGET}"
