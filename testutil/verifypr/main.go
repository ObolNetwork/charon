// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Command verifypr provides a tool to verify charon PRs against the template defined in docs/contributing.md.
package main

import (
	"log"
	"os"
)

func main() {
	err := verify()
	if err != nil {
		log.Printf("❌ Verification failed: %+v\n", err)
		os.Exit(1)
	}

	log.Println("✅ Verification Success")
}
