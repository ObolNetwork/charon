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

// Package pr provides functions to process GitHub pull requests.

//nolint:wrapcheck,cyclop
package pr

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// prFromEnv fetches the GitHub pull request body from env and returns the unmarshalled PR output.
func prFromEnv() (PR, error) {
	const prEnv = "GITHUB_PR"
	prJSON, ok := os.LookupEnv(prEnv)
	if !ok {
		return PR{}, fmt.Errorf("environments variable not set: %s", prEnv)
	} else if strings.TrimSpace(prJSON) == "" {
		return PR{}, fmt.Errorf("environments variable empty: %s", prEnv)
	}

	var pr PR
	err := json.Unmarshal([]byte(prJSON), &pr)
	if err != nil {
		return PR{}, fmt.Errorf("unmarshal %s failed: %w", prEnv, err)
	}

	return pr, nil
}

// Unticketed returns true if the ticket is "none" for the PR and returns false otherwise. It doesn't verify the PR body
// and assumes that PR verification step is already complete. Only call Unticketed after Verify.
func Unticketed() (bool, error) {
	pr, err := prFromEnv()
	if err != nil {
		return false, err
	}

	// Skip dependabot PRs.
	if strings.Contains(pr.Title, "build(deps)") && strings.Contains(pr.Body, "dependabot") {
		return false, nil
	}

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
