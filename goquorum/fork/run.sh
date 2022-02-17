#!/usr/bin/env bash

# Runs fork.go from this folder as working directory.

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd $SCRIPT_DIR
go run fork.go
cd -
