// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

//go:build tools
// +build tools

package main

// This file contains build time developer tools used in the charon repo.
// To install all the tools run: go generate tools.go

import (
	_ "github.com/bufbuild/buf/cmd/buf"
	_ "golang.org/x/tools/cmd/stringer"
	_ "google.golang.org/protobuf/cmd/protoc-gen-go"
)

//go:generate echo Installing tools: stringer
//go:generate go install golang.org/x/tools/cmd/stringer

//go:generate echo Installing tools: protobuf
//go:generate go install github.com/bufbuild/buf/cmd/buf
//go:generate go install github.com/bufbuild/buf/cmd/protoc-gen-buf-breaking
//go:generate go install github.com/bufbuild/buf/cmd/protoc-gen-buf-lint
//go:generate go install google.golang.org/protobuf/cmd/protoc-gen-go
