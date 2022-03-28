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

package main

import (
	"flag"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
)

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
		},
		{
			in: log{
				Subject: "build(deps): blah blah",
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

//go:generate go test . -v -run=TestParsePRs -git # -update

var git = flag.Bool("git", false, "Enables git log parsing, requires full checkout")

func TestParsePRs(t *testing.T) {
	if !*git {
		t.Skip("Skipping since --git flag not enabled")
		return
	}

	gitRange := "606e9bc^..eff988a"
	prs, err := parsePRs(gitRange)
	require.NoError(t, err)

	data, err := tplDataFromPRs(prs, gitRange, func(i int) (string, error) {
		return fmt.Sprintf("Issue#%d", i), nil
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
