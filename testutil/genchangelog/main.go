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

// Command genchangelog provides a tool to generate a changelog.md file from a git commit range.
// It requires the following:
//  - Each commit is a squash merged GitHub PR.
//  - The commit subject contains the PR number '(#123)'.
//  - Each commit contains a 'category: foo' line in the body.
//  - Each commit is linked to a Github Issue via a 'ticket: #321' line in the body.
//  - A GITHUB_TOKEN env var is present to download the issue title.
//  - Only PRs with supported categories linked to Issues will be included in the changelog.
//nolint:forbidigo,gosec,revive
package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	applog "github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

var (
	rangeFlag  = flag.String("range", "", "Git commit range to create changelog from. Defaults to '<second_latest_tag>..<latest_tag>'")
	outputFlag = flag.String("output", "changelog.md", "Output markdown file path")
	tokenFlag  = flag.String("github_token", "", "GitHub personal access token. Defaults to GITHUB_TOKEN env var")

	//go:embed template.md
	tpl string

	// categoryOrder defines the supported categories and their ordering.
	categoryOrder = map[string]int{
		"feature":  1,
		"bug":      2,
		"refactor": 3,
		"docs":     4,
		"test":     5,
		"misc":     6,
	}

	skippedCategories = map[string]bool{
		"fixbuild": true,
	}

	numberRegex   = regexp.MustCompile(`[#/](\d{2,})`)
	categoryRegex = regexp.MustCompile(`category:\s?(\w+)`)
	ticketRegex   = regexp.MustCompile(`ticket:(.*)`)
)

// pullRequest is parsed from log.
type pullRequest struct {
	Title    string
	Number   int
	Category string
	Issue    int
}

// log is parsed from git logs.
type log struct {
	Commit  string `json:"commit"`
	Body    string `json:"body"`
	Subject string `json:"subject"`
	Author  string `json:"author"`
}

// tplData is the changelog template data structure.
type tplData struct {
	Tag        string
	Date       string
	RangeText  string
	RangeLink  string
	Categories []tplCategory
}

// tplCategory is a category section in the changelog.
type tplCategory struct {
	Name   string
	Label  string
	Issues []tplIssue
}

// tplIssue is an issue in the changelog.
type tplIssue struct {
	Category string
	Title    string
	Number   int
	Label    string
	PRs      []tplPR
}

// tplPR is an PR link in the changelog.
type tplPR struct {
	Label string
}

func main() {
	flag.Parse()

	token := *tokenFlag
	if token == "" {
		var ok bool
		token, ok = os.LookupEnv("GITHUB_TOKEN")
		if !ok {
			fmt.Println("Github access token not found, either specify --token flag or set GITHUB_TOKEN env var")
			os.Exit(1)
		}
	}

	err := run(*rangeFlag, *outputFlag, token)
	if err != nil {
		applog.Error(context.Background(), "Run error", err)
		os.Exit(1)
	}
}

// run runs the command.
func run(gitRange string, output string, token string) error {
	if gitRange == "" {
		tags, err := getLatestTags(2)
		if err != nil {
			return err
		}

		gitRange = fmt.Sprintf("%s..%s", tags[1], tags[0])
		fmt.Printf("Flag --range empty, defaulting to %s\n", gitRange)
	}

	prs, err := parsePRs(gitRange)
	if err != nil {
		return err
	}

	data, err := tplDataFromPRs(prs, gitRange, makeIssueFunc(token))
	if err != nil {
		return err
	}

	b, err := execTemplate(data)
	if err != nil {
		return err
	}

	if err := os.WriteFile(output, b, 0o644); err != nil {
		return errors.Wrap(err, "write output")
	}

	return nil
}

// makeIssueFunc returns a function that resolves an issue's title and status via the github API.
func makeIssueFunc(token string) func(int) (issue string, status string, err error) {
	return func(number int) (issue string, status string, err error) {
		u := fmt.Sprintf("https://api.github.com/repos/obolnetwork/charon/issues/%d", number)
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return "", "", errors.Wrap(err, "new request")
		}
		req.SetBasicAuth(token, "x-oauth-basic")

		resp, err := new(http.Client).Do(req)
		if err != nil {
			return "", "", errors.Wrap(err, "query github issue")
		}
		defer resp.Body.Close()

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", "", errors.Wrap(err, "read body")
		}

		// Common error fields
		opts := []z.Field{
			z.Str("url", u),
			z.Str("body", string(b)),
			z.Int("issue", number),
		}

		// Check if it is an error response
		var errResp struct {
			Message string `json:"message"`
			Docs    string `json:"documentation_url"`
		}
		if err = json.Unmarshal(b, &errResp); err != nil {
			return "", "", errors.Wrap(err, "unmarshal issue", opts...)
		} else if errResp.Message != "" && errResp.Docs != "" {
			return "", errResp.Message, nil
		}

		// Else parse the issue response
		var issueResp struct {
			Title string `json:"title"`
			State string `json:"state"`
		}
		err = json.Unmarshal(b, &issueResp)
		if err != nil {
			return "", "", errors.Wrap(err, "unmarshal issue", opts...)
		} else if issueResp.Title == "" {
			return "", "", errors.New("invalid issue response, missing title", opts...)
		}

		return issueResp.Title, issueResp.State, nil
	}
}

// execTemplate returns the executed changelog template.
func execTemplate(data tplData) ([]byte, error) {
	templ, err := template.New("").Parse(tpl)
	if err != nil {
		return nil, errors.Wrap(err, "parse template")
	}
	var buf bytes.Buffer
	if err := templ.Execute(&buf, data); err != nil {
		return nil, errors.Wrap(err, "execute template")
	}

	return buf.Bytes(), nil
}

// tplDataFromPRs builds the template data from the provides PRs, git range, issue title func.
func tplDataFromPRs(prs []pullRequest, gitRange string, issueData func(int) (string, string, error)) (tplData, error) {
	issues := make(map[int]tplIssue)
	for _, pr := range prs {
		issue := issues[pr.Issue]
		issue.Number = pr.Issue
		issue.Label = fmt.Sprintf("#%d", pr.Issue)
		issue.Category = selectCategory(issue.Category, pr.Category)
		issue.PRs = append(issue.PRs, tplPR{Label: fmt.Sprintf("#%d", pr.Number)})
		issues[pr.Issue] = issue
	}

	cats := make(map[string]tplCategory)
	for _, issue := range issues {
		title, status, err := issueData(issue.Number)
		if err != nil {
			return tplData{}, err
		} else if status != "closed" {
			fmt.Printf("Skipping '%s' issue #%d: %s (PRs=%d)\n", status, issue.Number, title, len(issue.PRs))
			continue
		}
		issue.Title = title

		cat := cats[issue.Category]
		cat.Name = issue.Category
		cat.Label = strings.Title(issue.Category)
		cat.Issues = append(cat.Issues, issue)
		cats[issue.Category] = cat
	}

	var catSlice []tplCategory
	for _, cat := range cats {
		if cat.Name == "" {
			continue
		}
		catSlice = append(catSlice, cat)
	}

	sort.Slice(catSlice, func(i, j int) bool {
		return categoryOrder[catSlice[i].Name] < categoryOrder[catSlice[j].Name]
	})

	tag := "v0.0.0"
	split := strings.Split(gitRange, "..")
	if len(split) > 1 && strings.HasPrefix(split[1], "v") {
		tag = split[1]
	}

	return tplData{
		Tag:        tag,
		Date:       time.Now().Format("2006-01-02"),
		RangeText:  gitRange,
		RangeLink:  fmt.Sprintf("https://github.com/obolnetwork/charon/compare/%s", gitRange),
		Categories: catSlice,
	}, nil
}

// selectCategory returns the current or the candidate category based on categoryOrder.
func selectCategory(current, candidate string) string {
	candidateOrder, ok := categoryOrder[candidate]
	if !ok {
		return current
	}

	currentOrder, ok := categoryOrder[current]
	if !ok {
		return candidate
	}

	if currentOrder <= candidateOrder {
		return current
	}

	return candidate
}

// parsePRs returns parsed PRs by query the git logs for the provided range.
func parsePRs(gitRange string) ([]pullRequest, error) {
	// Custom json encoding of git log output.
	const format = `--pretty=format:{…commit…: …%h…,…body…: …%b…,…subject…: …%s…,…author…: …%aE…}†`

	b, err := exec.Command("git", "log", format, gitRange).CombinedOutput()
	if err != nil {
		return nil, errors.Wrap(err, "git log")
	}
	out := strings.TrimSuffix(string(b), "†") // Trim last log separator
	out = "[" + out + "]"                     // Wrap logs in json array
	out = strings.ReplaceAll(out, "†\n", `,`) // Replace log separator with comma
	out = strings.ReplaceAll(out, "\r", ``)   // Drop carriage returns if any
	out = strings.ReplaceAll(out, "\n", `\n`) // Escape new lines
	out = strings.ReplaceAll(out, "\t", `\t`) // Escape tabs
	out = strings.ReplaceAll(out, `"`, `\"`)  // Escape double quotes
	out = strings.ReplaceAll(out, `…`, `"`)   // Replace field separator

	var logs []log
	if err := json.Unmarshal([]byte(out), &logs); err != nil {
		return nil, errors.Wrap(err, "unmarshal git log")
	}

	var resp []pullRequest
	for _, l := range logs {
		l.Commit = "https://github.com/ObolNetwork/charon/commit/" + l.Commit
		pr, ok := prFromLog(l)
		if !ok {
			continue
		}

		resp = append(resp, pr)
	}

	return resp, nil
}

// prFromLog returns a charon pull request from the raw git log.
func prFromLog(l log) (pullRequest, bool) {
	if strings.Contains(l.Subject, "build(deps)") {
		fmt.Printf("Skipping dependabot PR (%s): %s\n", l.Commit, l.Subject)
		return pullRequest{}, false
	}

	var (
		category string
		issue    int
		number   int
	)

	number, ok := getNumber(l.Subject)
	if !ok {
		fmt.Printf("Failed parsing PR number from git subject (%v): %s\n", l.Commit, l.Subject)
		return pullRequest{}, false
	}

	category, ok = getFirstMatch(categoryRegex, l.Body)
	if !ok {
		fmt.Printf("Failed parsing category from git body (%v): %s\n", l.Commit, l.Subject)
		return pullRequest{}, false
	} else if skippedCategories[category] {
		fmt.Printf("Skipping PR with '%s' category (%v): %s\n", category, l.Commit, l.Subject)
		return pullRequest{}, false
	} else if categoryOrder[category] == 0 {
		fmt.Printf("Unsupported category %s (%v): %s\n", category, l.Commit, l.Subject)
		return pullRequest{}, false
	}

	ticket, ok := getFirstMatch(ticketRegex, l.Body)
	if !ok {
		fmt.Printf("Failed parsing ticket from git body (%v): %s\n", l.Commit, l.Subject)
		return pullRequest{}, false
	} else if strings.Contains(ticket, "none") {
		fmt.Printf("Skipping PR with 'none' ticket (%s): %s\n", l.Commit, l.Subject)
		return pullRequest{}, false
	} else {
		issue, ok = getNumber(ticket)
		if !ok {
			fmt.Printf("Failed parsing issue number from ticket (%v): %s \n", l.Commit, ticket)
			return pullRequest{}, false
		}
	}

	return pullRequest{
		Number:   number,
		Title:    l.Subject,
		Category: category,
		Issue:    issue,
	}, true
}

// getNumber returns a github issue number from the string.
func getNumber(s string) (int, bool) {
	matches := numberRegex.FindStringSubmatch(s)
	if len(matches) < 1 || matches[1] == "" {
		return 0, false
	}

	number, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, false
	}

	return number, true
}

// getFirstMatch returns the first regex match from the string.
func getFirstMatch(r *regexp.Regexp, s string) (string, bool) {
	matches := r.FindStringSubmatch(s)
	if len(matches) < 1 || matches[1] == "" {
		return "", false
	}

	return matches[1], true
}

// getLatestTags returns the latest N git tags.
func getLatestTags(n int) ([]string, error) {
	err := exec.Command("git", "fetch", "--tags").Run()
	if err != nil {
		return nil, errors.Wrap(err, "git fetch")
	}

	out, err := exec.Command("git", "rev-list", "--tags", "--max-count="+fmt.Sprint(n)).CombinedOutput()
	if err != nil {
		return nil, errors.Wrap(err, "git rev-list")
	}

	args := []string{"describe", "--tags", "--abbrev=0"}
	args = append(args, strings.Fields(string(out))...)

	out, err = exec.Command("git", args...).CombinedOutput()
	if err != nil {
		return nil, errors.Wrap(err, "git describe", z.Str("out", string(out)))
	}

	return strings.Fields(string(out)), nil
}
