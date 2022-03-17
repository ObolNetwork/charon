#!/bin/sh -l

set -e

cd "${GITHUB_WORKSPACE}"

go run testutil/verifypr/verifypr.go
