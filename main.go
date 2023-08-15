// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	_ "golang.org/x/exp/slices" // Imported to manually override libp2p dependency

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cmd"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	ctx = log.WithTopic(ctx, "cmd")

	err := cmd.New().ExecuteContext(ctx)

	cancel()

	if err != nil {
		log.Error(ctx, "Fatal error", err)
		os.Exit(1)
	}
}
