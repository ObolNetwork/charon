// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Command verifypr provides a tool to verify charon PRs against the template defined in docs/contibuting.md.
package main

import (
	"fmt"
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
		t.Run(fmt.Sprint(i), func(t *testing.T) {
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
		t.Run(fmt.Sprint(i), func(t *testing.T) {
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
