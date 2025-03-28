#!/usr/bin/env bash

if ! which buf 1>/dev/null; then
  echo "Installing tools"
  go install tool
fi

buf generate
buf lint
# buf breaking --against '.git#branch=origin/main'
