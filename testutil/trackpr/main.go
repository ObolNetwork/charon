// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Command trackpr tracks a PR without a ticket and adds it to GitHub project board.
package main

import (
	"context"
	"log"
	"os"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

const (
	// Name of the GitHub organization.
	organization = "ObolNetwork"
	// The number of the project. For ex: https://github.com/orgs/ObolNetwork/projects/1 has projectNumber 1.
	projectNumber = 7
)

func main() {
	ctx := context.Background()
	if err := run(ctx); err != nil {
		log.Printf("❌ Fatal error: %+v\n", err)
		os.Exit(1)
	}

	log.Println("✅ Success")
}

func run(ctx context.Context) error {
	ghToken, ok := os.LookupEnv("GH_TOKEN")
	if !ok {
		return errors.New("env not set", z.Str("key", "GH_TOKEN"))
	}

	pr, err := PRFromEnv()
	if err != nil {
		return err
	}

	err = track(ctx, ghToken, pr, organization, projectNumber)
	if err != nil {
		return err
	}

	return nil
}
