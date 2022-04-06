#!/usr/bin/env bash

set -x

if ! which buf 1>/dev/null; then
  echo "Installing tools"
  go generate tools.go
fi

buf generate
buf lint
# buf breaking --against '.git#branch=main' # Enable once protos in main
