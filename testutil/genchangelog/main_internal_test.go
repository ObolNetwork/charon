// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package main

import (
	"flag"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

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
		t.Run(fmt.Sprint(i), func(t *testing.T) {
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
	const f = "feature"
	const r = "refactor"

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

	tags, err := getLatestTags(2)
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
	prs, err := parsePRs(gitRange)
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
