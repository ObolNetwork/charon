// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package main

import (
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/cmd"
)

func main() {
	cobra.CheckErr(cmd.New().Execute())
}
