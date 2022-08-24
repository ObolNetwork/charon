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

// Package pr provides functions to check and process pull requests.
//
//nolint:wrapcheck,cyclop,forbidigo
package pr

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type PR struct {
	Title string
	Body  string
}

const (
	prenv = "GITHUB_PR"
)

// Unticketed returns true if the ticket is "none" for the PR and returns false otherwise.
// It doesn't verify the body and assumes the PR body is already verified before it is merged and closed.
func Unticketed() (bool, error) {
	fmt.Println("Verifying charon PR against template")
	fmt.Printf("Parsing %s\n", prenv)

	prJSON, _ := os.LookupEnv(prenv)

	if strings.Contains(prJSON, "build(deps)") && strings.Contains(prJSON, "dependabot") {
		fmt.Println("Skipping dependabot PR")
		return false, nil
	}

	var pr PR
	if err := json.Unmarshal([]byte(prJSON), &pr); err != nil {
		return false, fmt.Errorf("unmarshal %s failed: %w", prenv, err)
	}

	fmt.Printf("PR Title: %s\n", pr.Title)
	fmt.Printf("PR Body:\n%s\n####\n", pr.Body)

	const ticketTag = "ticket:"

	for _, line := range strings.Split(pr.Body, "\n") {
		if !strings.HasPrefix(line, ticketTag) {
			continue
		}

		ticket := strings.TrimSpace(strings.TrimPrefix(line, ticketTag))
		if ticket == "none" {
			return true, nil
		}
	}

	return false, nil
}
