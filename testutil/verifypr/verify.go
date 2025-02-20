// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Command verifypr provides a tool to verify charon PRs against the template defined in docs/contibuting.md.
//
//nolint:revive,cyclop
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/z"
)

var titlePrefix = regexp.MustCompile(`^[*\w]+(/[*\w]+)?$`)

type PR struct {
	Title string `json:"title"`
	Body  string `json:"body"`
	ID    string `json:"node_id"`
}

// PRFromEnv returns the PR by parsing it from "GITHUB_PR" env var or an error.
func PRFromEnv() (PR, error) {
	const prEnv = "GITHUB_PR"
	prJSON, ok := os.LookupEnv(prEnv)
	if !ok || strings.TrimSpace(prJSON) == "" {
		return PR{}, errors.New("env variable not set", z.Str("var", prEnv))
	}

	var pr PR
	if err := json.Unmarshal([]byte(prJSON), &pr); err != nil {
		return PR{}, errors.Wrap(err, "unmarshal PR body")
	}

	if pr.Title == "" || pr.Body == "" || pr.ID == "" {
		return PR{}, errors.New("pr field not set")
	}

	return pr, nil
}

// verify returns an error if the PR doesn't correspond to the template defined in docs/contibuting.md.
func verify() error {
	if err := featureset.Init(context.Background(), featureset.Config{MinStatus: "alpha"}); err != nil {
		return err
	}

	pr, err := PRFromEnv()
	if err != nil {
		return err
	}

	// Skip dependabot PRs.
	if strings.Contains(pr.Title, "build(deps)") && strings.Contains(pr.Body, "dependabot") {
		return nil
	}

	// Skip Renovate PRs.
	if strings.Contains(pr.Title, "chore(deps)") && strings.Contains(pr.Body, "Renovate") {
		return nil
	}

	log.Printf("Verifying charon PR against template\n")
	log.Printf("PR Title: %s\n", pr.Title)
	log.Printf("## PR Body:\n%s\n####\n", pr.Body)

	if err := verifyTitle(pr.Title); err != nil {
		return err
	}

	if err := verifyBody(pr.Body); err != nil {
		return err
	}

	return nil
}

func verifyTitle(title string) error {
	const maxTitleLen = 60
	if len(title) > maxTitleLen {
		return errors.New("title too long",
			z.Int("max", maxTitleLen),
			z.Int("actual", len(title)))
	}

	split := strings.SplitN(title, ":", 2)
	if len(split) < 2 {
		return errors.New("title isn't prefixed with 'package[/subpackage]:'")
	}

	if !titlePrefix.MatchString(split[0]) {
		return errors.New("title prefix doesn't match regex")
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
				return errors.New("invalid category", z.Str("category", cat), z.Any("allows", allows))
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
				if u, err := url.ParseRequestURI(ticket); err != nil || u.Path == "" {
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
