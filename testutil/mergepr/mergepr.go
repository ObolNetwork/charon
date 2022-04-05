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

//nolint:revive // Nested structs are ok since read-only.
package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/google/go-github/v43/github"
	"golang.org/x/oauth2"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

const (
	DoNotMerge     = "do not merge"
	WIP            = "wip"
	MergeWhenReady = "merge when ready"
)

func main() {
	ctx := context.Background()
	if err := run(ctx); err != nil {
		log.Error(ctx, "Run error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	pr, err := getPRFromEnv()
	if err != nil {
		return err
	}

	t, err := getTokenFromEnv()
	if err != nil {
		return err
	}

	client := github.NewClient(oauth2.NewClient(ctx, t))

	return attemptMerge(ctx, client, pr)
}

func getTokenFromEnv() (token, error) {
	const tokenEnv = "GITHUB_TOKEN" //nolint:gosec

	t, ok := os.LookupEnv(tokenEnv)
	if !ok {
		return "", errors.New("environments variable not set", z.Str("var", tokenEnv))
	} else if strings.TrimSpace(t) == "" {
		return "", errors.New("environments variable empty", z.Str("var", tokenEnv))
	}

	return token(t), nil
}

func getPRFromEnv() (PR, error) {
	const prenv = "GITHUB_PR"

	prJSON, ok := os.LookupEnv(prenv)
	if !ok {
		return PR{}, errors.New("environments variable unset", z.Str("var", prenv))
	} else if strings.TrimSpace(prJSON) == "" {
		return PR{}, errors.New("environments variable empty", z.Str("var", prenv))
	}

	var pr PR
	err := json.Unmarshal([]byte(prJSON), &pr)
	if err != nil {
		return PR{}, errors.Wrap(err, "unmarshal pr")
	}

	return pr, nil
}

type PR struct {
	Base struct {
		Repo struct {
			Name  string
			Owner struct {
				Login string `json:"login"`
			} `json:"owner"`
		} `json:"repo"`
	} `json:"base"`
	Number int `json:"number"`
	Head   struct {
		SHA string `json:"sha"`
	} `json:"head"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
	Body      string `json:"body"`
	Title     string `json:"title"`
	State     string `json:"state"`
	Mergeable bool   `json:"mergeable"`
	Merged    bool   `json:"merged"`
}

func (pr PR) Owner() string {
	return pr.Base.Repo.Owner.Login
}

func (pr PR) Repo() string {
	return pr.Base.Repo.Name
}

func attemptMerge(ctx context.Context, client *github.Client, pr PR) error {
	if pr.State != "open" {
		log.Warn(ctx, "PR not open")
		return nil
	} else if pr.Merged {
		log.Warn(ctx, "PR already merged")
		return nil
	} else if !pr.Mergeable {
		log.Warn(ctx, "PR not mergeable")
		return nil
	}

	if ok, err := allChecksPassed(ctx, client, pr); err != nil {
		return err
	} else if !ok {
		return nil
	}

	log.Info(ctx, "All checks have passed")

	if !readyToMerge(ctx, pr) {
		return nil
	}

	log.Info(ctx, "Ready to merge")

	return merge(ctx, client, pr)
}

func merge(ctx context.Context, client *github.Client, pr PR) error {
	opts := &github.PullRequestOptions{
		MergeMethod: "squash",
	}

	res, _, err := client.PullRequests.Merge(ctx, pr.Owner(), pr.Repo(), pr.Number, pr.Body, opts)
	if err != nil {
		return errors.Wrap(err, "merge")
	}

	if !res.GetMerged() {
		log.Warn(ctx, "Merging failed", z.Str("msg", res.GetMessage()))
		return nil
	}

	log.Info(ctx, "Merged PR", z.Str("sha", res.GetSHA()))

	return nil
}

func readyToMerge(ctx context.Context, pr PR) bool {
	body := strings.ToLower(pr.Body)
	if strings.Contains(body, WIP) || strings.Contains(body, DoNotMerge) {
		log.Warn(ctx, "Body contains 'wip' or 'do not merge'")
		return false
	}

	var ready bool
	for _, label := range pr.Labels {
		if label.Name == WIP || label.Name == DoNotMerge {
			log.Warn(ctx, "Labels contains 'wip' or 'do not merge'")
			return false
		}
		if label.Name == MergeWhenReady {
			ready = true
		}
	}

	if !ready {
		log.Warn(ctx, "Labels do not contain 'merge when ready'")
		return false
	}

	return true
}

func allChecksPassed(ctx context.Context, client *github.Client, pr PR) (bool, error) {
	var notOKChecks []string

	sl, _, err := client.Repositories.GetCombinedStatus(ctx, pr.Owner(), pr.Repo(), pr.Head.SHA, nil)
	if err != nil {
		return false, errors.Wrap(err, "get combined status")
	}

	for _, s := range sl.Statuses {
		if s.GetState() != "success" {
			log.Warn(ctx, "Failed status detected",
				z.Str("context", s.GetContext()),
				z.Str("state", s.GetState()),
			)
			notOKChecks = append(notOKChecks, s.GetContext())
		}
	}

	okConclusions := map[string]bool{
		"success": true,
		"neutral": true,
		"skipped": true,
	}

	checkRuns, _, err := client.Checks.ListCheckRunsForRef(ctx, pr.Owner(), pr.Repo(), pr.Head.SHA, nil)
	if err != nil {
		return false, errors.Wrap(err, "list check runs")
	}

	for _, check := range checkRuns.CheckRuns {
		if check.GetName() == "merge-pr" {
			// Skip our selves
			continue
		}
		if !okConclusions[check.GetConclusion()] {
			notOKChecks = append(notOKChecks, check.GetName())
			log.Warn(ctx, "Non-ok check detected",
				z.Str("name", check.GetName()),
				z.Str("conclusion", check.GetConclusion()),
			)
		}
	}

	if len(notOKChecks) > 0 {
		return false, nil
	}

	return true, nil
}

type token string

func (t token) Token() (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken: string(t),
		TokenType:   "Bearer",
	}, nil
}
