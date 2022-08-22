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

// Command trackpr verifies if a ticket with a "none" tag is present in the closed PR. If such a PR exists,
// the command sets UNTICKETED_PR to true.
//
//nolint:wrapcheck,revive,cyclop,forbidigo
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func main() {
	err := run()
	if err != nil {
		fmt.Print("❌ " + err.Error())
		os.Exit(1)
	}
}

type PR struct {
	Title string
	Body  string
}

const (
	prenv = "GITHUB_PR"
	ghEnv = "GITHUB_ENV"
)

func run() error {
	fmt.Println("Verifying charon PR against template")
	fmt.Printf("Parsing %s\n", prenv)

	prJSON, _ := os.LookupEnv(prenv)

	if strings.Contains(prJSON, "build(deps)") && strings.Contains(prJSON, "dependabot") {
		fmt.Println("Skipping dependabot PR")
		return nil
	}

	var pr PR
	if err := json.Unmarshal([]byte(prJSON), &pr); err != nil {
		return fmt.Errorf("unmarshal %s failed: %w", prenv, err)
	}

	fmt.Printf("PR Title: %s\n", pr.Title)
	fmt.Printf("PR Body:\n%s\n####\n", pr.Body)

	if err := saveToGithubEnv("UNTICKETED_PR", unticketedPR(pr.Body)); err != nil {
		return err
	}

	return nil
}

// saveToGithubEnv stores the key value pair to the GITHUB_ENV environment file.
func saveToGithubEnv(key string, val bool) error {
	filename, _ := os.LookupEnv(ghEnv)
	f, err := os.OpenFile(filename, os.O_RDWR, 0o666)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	// write key value pair to file
	keyVal := []byte(fmt.Sprintf("%s=%t", key, val))
	if _, err := f.Write(keyVal); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	// close file
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}

	return nil
}

// unticketedPR returns true if the ticket is "none" for the PR and returns false otherwise.
// It doesn't verify the body and assumes verifyPR step has already succeeded.
func unticketedPR(body string) bool {
	const ticketTag = "ticket:"

	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, ticketTag) {
			continue
		}

		ticket := strings.TrimSpace(strings.TrimPrefix(line, ticketTag))
		if ticket == "none" {
			return true
		}
	}

	return false
}
