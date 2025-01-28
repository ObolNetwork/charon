#!/bin/bash
set -e

# Create dist directory if it doesn't exist
mkdir -p dist

# Build for linux/amd64
echo "Building for linux/amd64..."
docker run --rm --platform linux/amd64 \
  -v $(pwd):/workspace -w /workspace \
  --platform linux/amd64 \
  golang:1.23.4-bookworm \
  bash -c "apt-get update && apt-get install -y build-essential && \
  env CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
  go build -tags='netgo osusergo' -o dist/charon-linux-amd64"

# Build for linux/arm64
echo "Building for linux/arm64..."
docker run --rm --platform linux/amd64 \
  -v $(pwd):/workspace -w /workspace \
  --platform linux/amd64 \
  golang:1.23.4-bookworm \
  bash -c "apt-get update && apt-get install -y gcc-aarch64-linux-gnu && \
  env CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc \
  go build -tags='netgo osusergo' -o dist/charon-linux-arm64"

# Create archives
cd dist
for binary in charon-*; do
  tar czf "${binary}.tar.gz" "$binary"
done
