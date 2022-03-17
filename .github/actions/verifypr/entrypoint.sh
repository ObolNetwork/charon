#!/bin/sh -l

set -e

printenv

cd "${GITHUB_WORKSPACE}"

go run testutil/verifypr/verifypr.go
