// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package main

import (
	"flag"
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/testutil"
)

var git = flag.Bool("git", false, "Enables tests that require git and a full checkout")

func TestPRFromLog(t *testing.T) {
	tests := []struct {
		in  log
		out pullRequest
	}{
		{
			in: log{
				Body:    "Body\n\ncategory: feature\nticket: #12",
				Subject: "core/validatorapi: fix lint issue (#266)",
			},
			out: pullRequest{
				Title:    "core/validatorapi: fix lint issue (#266)",
				Number:   266,
				Category: "feature",
				Issue:    12,
			},
		},
		{
			in: log{
				Body:    "Body\n\ncategory: feature\nticket: ObolNetwork/charon#251",
				Subject: "core/validatorapi: fix lint issue (#266)",
			},
			out: pullRequest{
				Title:    "core/validatorapi: fix lint issue (#266)",
				Number:   266,
				Category: "feature",
				Issue:    251,
			},
		},
		{
			in: log{
				Body:    "Body\n\ncategory: feature\nticket: https://github.com/ObolNetwork/charon/issues/999",
				Subject: "core/validatorapi: fix lint issue (#266)",
			},
			out: pullRequest{
				Title:    "core/validatorapi: fix lint issue (#266)",
				Number:   266,
				Category: "feature",
				Issue:    999,
			},
		},
		{
			in: log{
				Body:    "Body\n\ncategory: feature\nticket: none",
				Subject: "(#266)",
			},
			out: pullRequest{
				Title:    "(#266)",
				Number:   266,
				Category: "feature",
			},
		},
		{
			in: log{
				Subject: "build(deps): foo bar",
			},
		},
	}
	for i, test := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			actual, ok := prFromLog(test.in)
			if test.out.Title == "" {
				require.False(t, ok)
				return
			}

			require.True(t, ok)
			require.Equal(t, test.out, actual)
		})
	}
}

func TestSelectCategory(t *testing.T) {
	const (
		f = "feature"
		r = "refactor"
	)

	require.Equal(t, f, selectCategory(f, r))
	require.Equal(t, f, selectCategory(r, f))
	require.Equal(t, f, selectCategory(f, f))
	require.Equal(t, r, selectCategory(r, r))
}

//go:generate go test . -v -run=TestLatestTags -git

func TestLatestTags(t *testing.T) {
	if !*git {
		t.Skip("Skipping since --git flag not enabled")
		return
	}

	tags, err := getLatestTags(t.Context(), 2)
	require.NoError(t, err)
	require.Len(t, tags, 2)
	t.Log(tags)
}

//go:generate go test . -v -run=TestParsePRs -git -update -clean

func TestParsePRs(t *testing.T) {
	if !*git {
		t.Skip("Skipping since --git flag not enabled")
		return
	}

	gitRange := "v0.12.0..v0.13.0"
	prs, err := parsePRs(t.Context(), gitRange)
	require.NoError(t, err)

	data, err := tplDataFromPRs(prs, gitRange, func(i int) (string, string, error) {
		return fmt.Sprintf("Issue#%d", i), "closed", nil
	})
	require.NoError(t, err)

	data.Date = "1970-01-01"

	templ, err := execTemplate(data)
	require.NoError(t, err)

	t.Run("parsed_prs", func(t *testing.T) {
		testutil.RequireGoldenJSON(t, prs)
	})
	t.Run("template_data", func(t *testing.T) {
		testutil.RequireGoldenJSON(t, data)
	})
	t.Run("template", func(t *testing.T) {
		testutil.RequireGoldenBytes(t, templ)
	})
}

func TestAuthorsAndContributors(t *testing.T) {
	prs := resolveAuthors([]pullRequest{
		{Title: "app: first (#10)", Number: 10},
		{Title: "core: fix (#11)", Number: 11, Category: "bug", Issue: 5},
		{Title: "app: second (#12)", Number: 12},
		{Title: "p2p: unresolved (#13)", Number: 13},
	}, func(number int) (string, error) {
		switch number {
		case 10, 12:
			return "alice", nil
		case 11:
			return "bob", nil
		default:
			return "", errors.New("rate limited")
		}
	})

	data, err := tplDataFromPRs(prs, "v1.0.0..v1.0.1", func(int) (string, string, error) {
		return "Issue title", "closed", nil
	})
	require.NoError(t, err)

	// Authors of issue-linked PRs are contributors too, though only listed in categories.
	require.Equal(t, []string{"alice", "bob"}, data.Contributors)

	b, err := execTemplate(data)
	require.NoError(t, err)

	out := string(b)
	require.Contains(t, out, "- [app: first (#10)](https://github.com/ObolNetwork/charon/pull/10) by @alice\n")
	require.Contains(t, out, "- [p2p: unresolved (#13)](https://github.com/ObolNetwork/charon/pull/13)\n")
	require.Contains(t, out, "## Contributors\n\n@alice, @bob\n")
}
