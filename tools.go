// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

//go:build tools
// +build tools

package main

// This file contains build time developer tools used in the charon repo.
// To install all the tools run: go generate tools.go

// Allow testutil

import (
	_ "github.com/bufbuild/buf/cmd/buf"
	_ "golang.org/x/tools/cmd/stringer"
	_ "google.golang.org/protobuf/cmd/protoc-gen-go"
)

//go:generate echo Installing tools: stringer
//go:generate go install golang.org/x/tools/cmd/stringer

//go:generate echo Installing tools: mockery
//go:generate go install github.com/vektra/mockery/v2@v2.42.1

//go:generate echo Installing tools: protobuf
//go:generate go install github.com/bufbuild/buf/cmd/buf@latest
//go:generate go install github.com/bufbuild/buf/cmd/protoc-gen-buf-breaking@latest
//go:generate go install github.com/bufbuild/buf/cmd/protoc-gen-buf-lint@latest
//go:generate go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

//go:generate echo Installing tools: compose
//go:generate go install github.com/obolnetwork/charon/testutil/compose/compose

//go:generate echo Installing tools: abigen
//go:generate go install github.com/ethereum/go-ethereum/cmd/abigen@latest
