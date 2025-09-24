#!/usr/bin/env bash

VERSION="v2.5.0"

if ! command -v golangci-lint &>/dev/null; then
    echo "golangci-lint could not be found"
    exit 1
fi

version_check=$(golangci-lint version)
if [[ $version_check != *"$VERSION"* ]]; then
    echo $version_check
    echo "golangci-lint version is not $VERSION"
fi

golangci-lint run --allow-parallel-runners
