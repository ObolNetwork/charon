// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/obolnetwork/charon/app/featureset"
)

func TestTitle(t *testing.T) {
	tests := []struct {
		Title string
		Error string
	}{
		{
			Title: "",
			Error: "title isn't prefixed",
		},
		{
			Title: "missing_colon",
			Error: "title isn't prefixed",
		},
		{
			Title: "no space: allowed",
			Error: "doesn't match regex",
		},
		{
			Title: "this: is ok",
			Error: "",
		},
		{
			Title: "this/is: also ok",
			Error: "",
		},
		{
			Title: "no: punctuation.",
			Error: "shouldn't end with punctuation",
		},
		{
			Title: "short: too",
			Error: "title suffix too short",
		},
		{
			Title: "missing:space",
			Error: "not followed by space",
		},
		{
			Title: "*: wildcard is ok",
			Error: "",
		},
		{
			Title: "*/*: wildcards are also ok",
			Error: "",
		},
		{
			Title: "avoid: Sentence case",
			Error: "shouldn't start with a capital",
		},
		{
			Title: "foo/bar: this title is too long, the max length is 60 characters",
			Error: "title too long",
		},
	}
	for i, test := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			err := verifyTitle(test.Title)
			if test.Error == "" {
				if err == nil {
					return
				} else {
					t.Fatalf("Expected nil error, got: %v", err)
				}
			}

			if err == nil {
				t.Fatalf("Expected error to contain '%s', got nil", test.Error)
			} else if !strings.Contains(err.Error(), test.Error) {
				t.Fatalf("Expected error to contain '%s', got: %v", test.Error, err)
			}
		})
	}
}

func TestBody(t *testing.T) {
	featureset.EnableForT(t, "foo")
	featureset.EnableForT(t, "bar")

	tests := []struct {
		Body  string
		Error string
	}{
		{
			Body:  "",
			Error: "body empty",
		},
		{
			Body:  "Foo\nbar\n\ncategory: bug\nticket: #123",
			Error: "",
		},
		{
			Body:  "\nFoo",
			Error: "first line empty",
		},
		{
			Body:  "Foo\ncategory: bar",
			Error: "not preceded by empty line",
		},
		{
			Body:  "Foo\nbar\n\ncategory: bar",
			Error: "invalid category",
		},
		{
			Body:  "Foo\nbar\n\ncategory: bar",
			Error: "invalid category",
		},
		{
			Body:  "Foo\nbar\n\ncategory:",
			Error: "empty",
		},
		{
			Body:  "Foo",
			Error: "missing category tag",
		},
		{
			Body:  "Foo\n\ncategory: bug\nticket:123",
			Error: "invalid ticket tag",
		},
		{
			Body:  "Foo\n\ncategory: bug\nticket:https://s",
			Error: "ticket tag invalid url",
		},
		{
			Body:  "<!--\n\ncategory: bug\nticket: none",
			Error: "instructions not deleted (markdown comments present)",
		},
		{
			Body:  "Foo\n\ncategory: bug\nticket: #000",
			Error: "invalid #000 ticket",
		},
		{
			Body:  "Foo\n\ncategory: bug\nticket: none\nfeature_flag: foo",
			Error: "",
		},
		{
			Body:  "Foo\n\ncategory: bug\nticket: none\nfeature_flag: bar",
			Error: "",
		},
		{
			Body:  "Foo\n\ncategory: bug\nticket: none\nfeature_flag: ?",
			Error: "invalid ? feature_flag",
		},
		{
			Body:  "Foo\n\ncategory: bug\nticket: none\nfeature_flag: CAPS",
			Error: "feature flags are snake case",
		},
		{
			Body:  "Foo\n\ncategory: bug\nticket: none\nfeature_flag: unknown",
			Error: "unknown feature flag",
		},
	}
	for i, test := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			err := verifyBody(test.Body)
			if test.Error == "" {
				if err == nil {
					return
				} else {
					t.Fatalf("Expected nil error, got: %v", err)
				}
			}

			if err == nil {
				t.Fatalf("Expected error to contain '%s', got nil", test.Error)
			} else if !strings.Contains(err.Error(), test.Error) {
				t.Fatalf("Expected error to contain '%s', got: %v", test.Error, err)
			}
		})
	}
}

func TestVerifyBotSkip(t *testing.T) {
	tests := []struct {
		Name    string
		PR      PR
		Skipped bool // true means verify() should return nil without format checks
	}{
		{
			Name: "dependabot skipped",
			PR: PR{
				Title:   "build(deps): bump some-lib from 1.0 to 2.0",
				Body:    "Bumps some-lib.",
				ID:      "node_1",
				Creator: PRUser{Login: "dependabot[bot]"},
			},
			Skipped: true,
		},
		{
			Name: "renovate skipped",
			PR: PR{
				Title:   "chore(deps): update some-lib to v2",
				Body:    "This PR contains the following updates.",
				ID:      "node_2",
				Creator: PRUser{Login: "renovate[bot]"},
			},
			Skipped: true,
		},
		{
			Name: "dependabot title but wrong creator not skipped",
			PR: PR{
				Title:   "build(deps): bump some-lib from 1.0 to 2.0",
				Body:    "Bumps some-lib.",
				ID:      "node_3",
				Creator: PRUser{Login: "someuser"},
			},
			Skipped: false,
		},
		{
			Name: "renovate title but wrong creator not skipped",
			PR: PR{
				Title:   "chore(deps): update some-lib to v2",
				Body:    "This PR contains the following updates.",
				ID:      "node_4",
				Creator: PRUser{Login: "someuser"},
			},
			Skipped: false,
		},
		{
			Name: "dependabot creator but wrong title not skipped",
			PR: PR{
				Title:   "chore(deps): bump some-lib from 1.0 to 2.0",
				Body:    "Bumps some-lib.",
				ID:      "node_5",
				Creator: PRUser{Login: "dependabot[bot]"},
			},
			Skipped: false,
		},
		{
			Name: "renovate creator but wrong title not skipped",
			PR: PR{
				Title:   "build(deps): update some-lib to v2",
				Body:    "This PR contains the following updates.",
				ID:      "node_6",
				Creator: PRUser{Login: "renovate[bot]"},
			},
			Skipped: false,
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b, err := json.Marshal(test.PR)
			if err != nil {
				t.Fatalf("marshal PR: %v", err)
			}

			t.Setenv("GITHUB_PR", string(b))

			err = verify()
			if test.Skipped {
				if err != nil {
					t.Fatalf("expected bot PR to be skipped (nil error), got: %v", err)
				}
			} else {
				// Non-bot PRs will fail title/body format checks — that's expected.
				if err == nil {
					t.Fatalf("expected non-bot PR to fail format checks, got nil error")
				}
			}
		})
	}
}
