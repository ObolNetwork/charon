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

// The unticketedpr command verifies if a ticket with a "none" tag is present in the closed PR. If such a PR exists,
// the command sets NONE_TICKET_PRESENT to true.
//
//nolint:wrapcheck,revive,cyclop,forbidigo
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const noneTicket = "none"

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

func run() error {
	const prenv = "GITHUB_PR"
	fmt.Println("Verifying charon PR against template")
	fmt.Printf("Parsing %s\n", prenv)

	prJSON, _ := os.LookupEnv(prenv)

	if strings.Contains(prJSON, "build(deps)") && strings.Contains(prJSON, "dependabot") {
		fmt.Println("Skipping dependabot PR")
		return nil
	}

	var pr PR
	err := json.Unmarshal([]byte(prJSON), &pr)
	if err != nil {
		return fmt.Errorf("unmarshal %s failed: %w", prenv, err)
	}

	fmt.Printf("PR Title: %s\n", pr.Title)
	fmt.Printf("PR Body:\n%s\n####\n", pr.Body)

	env_filename, _ := os.LookupEnv("GITHUB_ENV")
	f, err := os.OpenFile(env_filename, os.O_RDWR, 0o666)
	if err != nil {
		return fmt.Errorf("error opening github env file")
	}

	// save to env file: echo "{environment_variable_name}={value}" >> $GITHUB_ENV
	keyVal := []byte(fmt.Sprintf("%s=%t", "NONE_TICKET_PRESENT", containsNoneTicket(pr.Body, noneTicket)))
	if _, err := f.Write(keyVal); err != nil {
		return fmt.Errorf("writing to github env file failed: %w", err)
	}

	// close file
	if err := f.Close(); err != nil {
		return fmt.Errorf("writing to github env file failed: %w", err)
	}

	return nil
}

// noneTicket returns true if the ticket is "none" and returns false otherwise.
// It doesn't verify the body and assumes verifyPR step has already succeeded.
func containsNoneTicket(body, noneTicket string) bool {
	for _, line := range strings.Split(body, "\n") {
		const ticketTag = "ticket:"
		if strings.HasPrefix(line, ticketTag) {
			ticket := strings.TrimSpace(strings.TrimPrefix(line, ticketTag))
			if ticket == noneTicket {
				return true
			}
		}
	}

	return false
}
