// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//nolint:wrapcheck,revive,gocognit,cyclop,nestif
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var titlePrefix = regexp.MustCompile(`^[*\w]+(/[*\w]+)?$`)

func main() {
	err := run(os.Stdout)
	if err != nil {
		log.Fatal(err.Error())
	}
}

type PR struct {
	Title string
	Body  string
}

func run(w io.Writer) error {
	const prenv = "GITHUB_PR"
	_, _ = w.Write([]byte(fmt.Sprintf("Parsing %s", prenv)))

	prJSON, ok := os.LookupEnv(prenv)
	if !ok {
		return fmt.Errorf("environments variable not set: %s", prenv)
	} else if strings.TrimSpace(prJSON) == "" {
		return fmt.Errorf("environments variable empty: %s", prenv)
	}

	var pr PR
	err := json.Unmarshal([]byte(prJSON), &pr)
	if err != nil {
		return fmt.Errorf("unmarshal %s failed: %w", prenv, err)
	}

	_, _ = w.Write([]byte(fmt.Sprintf("PR Title: %s", pr.Title)))
	_, _ = w.Write([]byte(fmt.Sprintf("PR Body: %s", pr.Title)))

	if err := verifyTitle(pr.Title); err != nil {
		return err
	}

	if err := verifyBody(pr.Body); err != nil {
		return err
	}

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

func verifyBody(body string) error {
	if strings.TrimSpace(body) == "" {
		return errors.New("body empty")
	}

	var (
		prevLineEmpty bool
		foundCategory bool
		foundTicket   bool
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
