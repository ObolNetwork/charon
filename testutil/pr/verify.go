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

//nolint:wrapcheck,revive,gocognit,cyclop,nestif,forbidigo
package pr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/obolnetwork/charon/app/featureset"
)

var titlePrefix = regexp.MustCompile(`^[*\w]+(/[*\w]+)?$`)

type PR struct {
	Title string
	Body  string
}

// Verify verifies that the charon PRs correspond to the template defined in docs/contibuting.md.
func Verify() error {
	if err := featureset.Init(context.Background(), featureset.Config{MinStatus: "alpha"}); err != nil {
		return err
	}

	const prenv = "GITHUB_PR"
	fmt.Println("Verifying charon PR against template")
	fmt.Printf("Parsing %s\n", prenv)

	prJSON, ok := os.LookupEnv(prenv)
	if !ok {
		return fmt.Errorf("environments variable not set: %s", prenv)
	} else if strings.TrimSpace(prJSON) == "" {
		return fmt.Errorf("environments variable empty: %s", prenv)
	}

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
	fmt.Printf("## PR Body:\n%s\n####\n", pr.Body)

	if err := verifyTitle(pr.Title); err != nil {
		return err
	}

	if err := verifyBody(pr.Body); err != nil {
		return err
	}

	fmt.Println("✅ Success")

	return nil
}

func verifyTitle(title string) error {
	split := strings.SplitN(title, ":", 2)
	if len(split) < 2 {
		return errors.New("title isn't prefixed with 'package[/subpackage]:'")
	}

	if !titlePrefix.Match([]byte(split[0])) {
		return fmt.Errorf("title prefix doesn't match regex %s", titlePrefix)
	}

	suffix := split[1]

	if len(suffix) < 5 {
		return errors.New("title suffix too short")
	}

	if len(suffix) < 5 {
		return errors.New("title suffix too short")
	}

	if suffix[0] != ' ' {
		return errors.New("title prefix not followed by space")
	}

	suffix = suffix[1:]

	if unicode.IsUpper(rune(suffix[0])) {
		return errors.New("title suffix shouldn't start with a capital")
	}

	if unicode.IsPunct(rune(suffix[len(suffix)-1])) {
		return errors.New("title suffix shouldn't end with punctuation")
	}

	return nil
}

//nolint:gocyclo
func verifyBody(body string) error {
	if strings.TrimSpace(body) == "" {
		return errors.New("body empty")
	}
	if strings.Contains(body, "<!--") {
		return errors.New("instructions not deleted (markdown comments present)")
	}

	var (
		prevLineEmpty bool
		foundCategory bool
		foundTicket   bool
		foundFeature  bool
	)
	for i, line := range strings.Split(body, "\n") {
		if i == 0 && strings.TrimSpace(line) == "" {
			return errors.New("first line empty")
		}

		const catTag = "category:"
		if strings.HasPrefix(line, catTag) {
			if foundCategory {
				return errors.New("multiple category tag lines")
			}
			if !prevLineEmpty {
				return errors.New("category tag not preceded by empty line")
			}

			cat := strings.TrimSpace(strings.TrimPrefix(line, catTag))

			if cat == "" {
				return errors.New("category tag empty")
			}

			var (
				ok     bool
				allows = []string{"feature", "bug", "refactor", "docs", "test", "fixbuild", "misc"}
			)
			for _, allow := range allows {
				if allow == cat {
					ok = true
					break
				}
			}

			if !ok {
				return fmt.Errorf("invalid category %s, not in %s", cat, allows)
			}

			foundCategory = true
		}

		const ticketTag = "ticket:"
		if strings.HasPrefix(line, ticketTag) {
			if foundTicket {
				return errors.New("multiple ticket tag lines")
			}

			ticket := strings.TrimSpace(strings.TrimPrefix(line, ticketTag))

			if ticket == "" {
				return errors.New("ticket tag empty")
			} else if ticket == "#000" {
				return errors.New("invalid #000 ticket")
			}

			if strings.HasPrefix(ticket, "https://") {
				if u, err := url.Parse(ticket); err != nil || u.Path == "" {
					return errors.New("ticket tag invalid url")
				}
				// URL is fine
			} else if ticket == "none" {
				// None is also fine
			} else if strings.HasPrefix(ticket, "#") {
				_, err := strconv.Atoi(strings.TrimPrefix(ticket, "#"))
				if err != nil {
					return errors.New("ticket tag not a valid github link, #123")
				}
				// Link is also fine
			} else {
				return errors.New("invalid ticket tag")
			}

			foundTicket = true
		}

		const featureTag = "feature_flag:"
		if strings.HasPrefix(line, featureTag) {
			if foundFeature {
				return errors.New("multiple feature_flag tag lines")
			}

			flag := strings.TrimSpace(strings.TrimPrefix(line, featureTag))

			if flag == "" {
				return errors.New("feature_flag tag empty")
			} else if flag == "?" {
				return errors.New("invalid ? feature_flag")
			}

			if strings.Contains(flag, " ") || strings.Contains(flag, "-") || strings.ToLower(flag) != flag {
				return errors.New("feature flags are snake case, see app/featureset/featureset.go")
			} else if !featureset.Enabled(featureset.Feature(flag)) {
				return errors.New("unknown feature flag, see app/featureset/featureset.go")
			}

			foundFeature = true
		}

		prevLineEmpty = strings.TrimSpace(line) == ""
	}

	if !foundCategory {
		return errors.New("missing category tag")
	}

	if !foundTicket {
		return errors.New("missing ticket tag")
	}

	return nil
}
