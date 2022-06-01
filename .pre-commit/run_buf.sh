#!/usr/bin/env bash

if ! which buf 1>/dev/null; then
  echo "Installing tools"
  go generate tools.go
fi

buf generate
buf lint
buf breaking --against '.git#branch=main'
