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

//nolint:dupl
package main

import (
	"fmt"
	"strings"
	"testing"
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
			Body:  "Foo\n\ncategory: bug\nticket: none\nfeature_set: alpha",
			Error: "",
		},
		{
			Body:  "Foo\n\ncategory: bug\nticket: none\nfeature_set: beta",
			Error: "",
		},
		{
			Body:  "Foo\n\ncategory: bug\nticket: none\nfeature_set: stable",
			Error: "",
		},
		{
			Body:  "Foo\n\ncategory: bug\nticket: none\nfeature_set: bad set",
			Error: "invalid feature_set tag not one of",
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
