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
)

var (
	rangeFlag  = flag.String("range", "", "Git commit range to create changelog from. Defaults to '<latest_tag>..HEAD'")
	outputFlag = flag.String("output", "changelog.md", "Output markdown file path")
	tokenFlag  = flag.String("github_token", "", "GitHub personal access token. Defaults to GITHUB_TOKEN env var")

	//go:embed template.md
	tpl string

	categoryOrder = map[string]int{
		"feature":  1,
		"bug":      2,
		"refactor": 3,
		"docs":     4,
		"test":     5,
		"misc":     6,
	}
)

type pullRequest struct {
	Title    string
	Number   int
	Category string
	Issue    int
}

type log struct {
	Commit  string `json:"commit"`
	Body    string `json:"body"`
	Subject string `json:"subject"`
	Author  string `json:"author"`
}

type tplData struct {
	Date       string
	RangeText  string
	RangeLink  string
	Categories []tplCategory
}

type tplCategory struct {
	Name   string
	Label  string
	Issues []tplIssue
}

type tplIssue struct {
	Category string
	Title    string
	Number   int
	Label    string
	PRs      []tplPR
}

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
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func run(gitRange string, output string, token string) error {
	if gitRange == "" {
		tag, err := getLatestTag()
		if err != nil {
			return err
		}

		gitRange = fmt.Sprintf("%s..HEAD", tag)
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

// makeIssueFunc returns a function that resolves issue titles via the github API.
func makeIssueFunc(token string) func(int) (string, error) {
	return func(number int) (string, error) {
		u := fmt.Sprintf("https://api.github.com/repos/obolnetwork/charon/issues/%d", number)
		req, err := http.NewRequest("GET", u, nil) //nolint:noctx
		if err != nil {
			return "", errors.Wrap(err, "new request")
		}
		req.SetBasicAuth(token, "x-oauth-basic")

		resp, err := new(http.Client).Do(req)
		if err != nil {
			return "", errors.Wrap(err, "query github issue")
		}
		defer resp.Body.Close()

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", errors.Wrap(err, "read body")
		}

		var title struct {
			Title string `json:"title"`
		}
		err = json.Unmarshal(b, &title)
		if err != nil {
			return "", errors.Wrap(err, "unmarshal issue")
		} else if title.Title == "" {
			return "", errors.New("github api error: " + string(b))
		}

		return title.Title, nil
	}
}

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

func tplDataFromPRs(prs []pullRequest, gitRange string, issueTitle func(int) (string, error)) (tplData, error) {
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
		title, err := issueTitle(issue.Number)
		if err != nil {
			return tplData{}, err
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

	return tplData{
		Date:       time.Now().Format("2006-01-02"),
		RangeText:  gitRange,
		RangeLink:  fmt.Sprintf("https://github.com/obolnetwork/charon/compare/%s", gitRange),
		Categories: catSlice,
	}, nil
}

func selectCategory(current, option string) string {
	optionOrder, ok := categoryOrder[option]
	if !ok {
		return current
	}

	currentOrder, ok := categoryOrder[current]
	if !ok {
		return option
	}

	if currentOrder >= optionOrder {
		return current
	}

	return option
}

func parsePRs(gitRange string) ([]pullRequest, error) {
	// Custom json encoding if git log output.
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

var (
	numberRegex   = regexp.MustCompile(`[#/](\d{2,})`)
	categoryRegex = regexp.MustCompile(`category:\s?(\w+)`)
	ticketRegex   = regexp.MustCompile(`ticket:(.*)`)
)

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

func getFirstMatch(r *regexp.Regexp, s string) (string, bool) {
	matches := r.FindStringSubmatch(s)
	if len(matches) < 1 || matches[1] == "" {
		return "", false
	}

	return matches[1], true
}

// getLatestTag returns the latest git tag.
func getLatestTag() (string, error) {
	err := exec.Command("git", "fetch", "--tags").Run()
	if err != nil {
		return "", errors.Wrap(err, "git fetch")
	}

	out, err := exec.Command("git", "rev-list", "--tags", "--max-count=1").CombinedOutput()
	if err != nil {
		return "", errors.Wrap(err, "git rev-list")
	}

	out, err = exec.Command("git", "describe", "--tags", strings.TrimSpace(string(out))).CombinedOutput()
	if err != nil {
		return "", errors.Wrap(err, "git describe")
	}

	return strings.TrimSpace(string(out)), nil
}
