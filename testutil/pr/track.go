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

// Package pr provides functions to process GitHub pull requests.

//nolint:wrapcheck,cyclop,exhaustruct,revive
package pr

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	gh "github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"

	"github.com/obolnetwork/charon/app/errors"
)

const (
	// Name of the GitHub organization.
	organization = "ObolNetwork"
	// The number of the project. For ex: https://github.com/orgs/ObolNetwork/projects/1 has projectNumber 1.
	projectNumber = gh.Int(1)
)

// config represents the input fields used in graphql mutations.
type config struct {
	projectID       gh.ID
	statusFieldID   gh.ID
	doneOptionID    gh.String
	sizeFieldID     gh.ID
	sprintFieldID   gh.ID
	currIterationID gh.ID
}

// Track tracks a PR without a ticket and adds it to the GitHub board.
func Track(ghToken string) error {
	// Ensure only PRs with no associated ticket gets through.
	ok, err := unticketed()
	if err != nil {
		return errors.Wrap(err, "check pr ticket")
	} else if !ok {
		log.Println("ticket exists for this PR")
		return nil
	}

	ctx := context.Background()

	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: ghToken},
	)

	httpClient := oauth2.NewClient(ctx, src)
	client := gh.NewClient(httpClient)

	// Step 1: Get project data
	conf, err := getProjectData(ctx, client, organization, projectNumber)
	if err != nil {
		return errors.Wrap(err, "failed to get project data")
	}

	prID, ok := os.LookupEnv("PR_ID")
	if !ok {
		return fmt.Errorf("cannot find PR_ID in env")
	}

	// Step 2: Add PR to project board
	itemID, err := addProjectItem(ctx, client, conf.projectID, prID)
	if err != nil {
		return errors.Wrap(err, "failed to add to project")
	}

	// Step 3: Set size, status and sprint iteration fields
	err = setFields(ctx, client, itemID, conf)
	if err != nil {
		return errors.Wrap(err, "failed to set fields")
	}

	return nil
}

// getProjectData gets project data given the name of the GitHub organization and the project id.
func getProjectData(ctx context.Context, client *gh.Client, org string, projectNumber gh.Int) (config, error) { //nolint:gocognit
	query := &projectQuery{}
	variables := map[string]interface{}{
		"org":    gh.String(org),
		"number": projectNumber,
	}

	err := client.Query(ctx, &query, variables)
	if err != nil {
		return config{}, errors.Wrap(err, "query project data")
	}

	var conf config

	if query.Organization.ProjectV2.ID == nil {
		return config{}, fmt.Errorf("project id absent")
	}
	conf.projectID = query.Organization.ProjectV2.ID

	if len(query.Organization.ProjectV2.Fields.Nodes) == 0 {
		return config{}, fmt.Errorf("empty list of fields")
	}

	for _, node := range query.Organization.ProjectV2.Fields.Nodes {
		// Sprint sizing
		if node.ProjectV2Field.Name == "Size" {
			conf.sizeFieldID = node.ProjectV2Field.ID
		}

		// PR status: https://docs.github.com/en/graphql/reference/objects#projectv2singleselectfield
		if node.ProjectV2SingleSelectField.Name == "Status" {
			conf.statusFieldID = node.ProjectV2SingleSelectField.ID

			if len(node.ProjectV2SingleSelectField.Options) == 0 {
				return config{}, fmt.Errorf("status fields absent")
			}

			for _, opt := range node.ProjectV2SingleSelectField.Options {
				if opt.Name == "Done" {
					conf.doneOptionID = opt.ID
				}
			}
		}

		// sprint iteration: https://docs.github.com/en/graphql/reference/objects#projectv2iterationfielditeration
		if node.ProjectV2IterationField.Name == "Sprint" {
			conf.sprintFieldID = node.ProjectV2IterationField.ID

			if len(node.ProjectV2IterationField.Configuration.Iterations) == 0 {
				return config{}, fmt.Errorf("sprint iterations absent")
			}

			for _, iter := range node.ProjectV2IterationField.Configuration.Iterations {
				layout := "2006-01-02"

				startDate, err := time.Parse(layout, iter.StartDate)
				if err != nil {
					return config{}, errors.Wrap(err, "parse date")
				}

				endDate := startDate.AddDate(0, 0, iter.Duration)

				currSprint := time.Now().Before(endDate)
				if currSprint {
					conf.currIterationID = iter.ID
					// Get the earliest current sprint
					break
				}
			}
		}
	}

	if conf.statusFieldID == nil || conf.doneOptionID == "" || conf.sizeFieldID == nil || conf.sprintFieldID == nil || conf.currIterationID == nil {
		return config{}, fmt.Errorf("config field absent")
	}

	return conf, nil
}

// addProjectItem adds the PR to the GitHub project board and returns the ID of the added item. It doesn't set any of the item's fields.
func addProjectItem(ctx context.Context, client *gh.Client, projectID gh.ID, prID string) (gh.ID, error) {
	m := &addItemMutation{}
	input := addProjectV2ItemByIdInput{
		ContentID: prID,
		ProjectID: projectID,
	}

	err := client.Mutate(ctx, m, input, nil)
	if err != nil {
		return nil, err
	}

	return m.AddProjectV2ItemByID.Item.ID, nil
}

// setFields sets the size, status and sprint fields to the project item.
func setFields(ctx context.Context, client *gh.Client, itemID gh.ID, conf config) error {
	if err := setStatus(ctx, client, itemID, conf); err != nil {
		return errors.Wrap(err, "set status")
	}

	if err := setSprint(ctx, client, itemID, conf); err != nil {
		return errors.Wrap(err, "set sprint")
	}

	if err := setSize(ctx, client, itemID, conf); err != nil {
		return errors.Wrap(err, "set size")
	}

	return nil
}

// setSize sets the size field of the input item.
func setSize(ctx context.Context, client *gh.Client, itemID gh.ID, conf config) error {
	m := &setSizeMutation{}
	input := updateProjectV2ItemFieldValueInput{
		ProjectID: conf.projectID,
		ItemID:    itemID,
		FieldID:   conf.sizeFieldID,
		Value: projectV2FieldValue{
			Number: gh.Float(1),
		},
	}

	err := client.Mutate(ctx, m, input, nil)

	return err
}

// setStatus sets the status field of the input item.
func setStatus(ctx context.Context, client *gh.Client, itemID gh.ID, conf config) error {
	m := &setStatusMutation{}
	input := updateProjectV2ItemFieldValueInput{
		ProjectID: conf.projectID,
		ItemID:    itemID,
		FieldID:   conf.statusFieldID,
		Value: projectV2FieldValue{
			SingleSelectOptionID: conf.doneOptionID,
		},
	}

	err := client.Mutate(ctx, m, input, nil)

	return err
}

// setSprint sets the sprint field of the input item.
func setSprint(ctx context.Context, client *gh.Client, itemID gh.ID, conf config) error {
	m := &setSprintMutation{}
	input := updateProjectV2ItemFieldValueInput{
		ProjectID: conf.projectID,
		ItemID:    itemID,
		FieldID:   conf.sprintFieldID,
		Value: projectV2FieldValue{
			IterationID: conf.currIterationID,
		},
	}

	err := client.Mutate(ctx, m, input, nil)

	return err
}

// unticketed returns true if the ticket is "none" for the PR and returns false otherwise. It doesn't verify the PR body
// and assumes that PR verification step is already complete. Only call unticketed after Verify.
func unticketed() (bool, error) {
	pr, err := prFromEnv()
	if err != nil {
		return false, err
	}

	// Skip dependabot PRs.
	if strings.Contains(pr.Title, "build(deps)") && strings.Contains(pr.Body, "dependabot") {
		return false, nil
	}

	const ticketTag = "ticket:"

	for _, line := range strings.Split(pr.Body, "\n") {
		if !strings.HasPrefix(line, ticketTag) {
			continue
		}

		ticket := strings.TrimSpace(strings.TrimPrefix(line, ticketTag))
		if ticket == "none" {
			return true, nil
		}
	}

	return false, nil
}
