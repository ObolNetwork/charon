// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Command trackpr tracks a PR without a ticket and adds it to GitHub project board.
//
//nolint:wrapcheck,cyclop,exhaustruct
package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"

	gh "github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

// projectData represents data related to a GitHub project.
type projectData struct {
	projectID       gh.ID
	statusFieldID   gh.ID
	doneOptionID    gh.String
	sizeFieldID     gh.ID
	sprintFieldID   gh.ID
	currIterationID gh.ID
}

type PR struct {
	Title  string `json:"title"`
	Body   string `json:"body"`
	NodeID string `json:"node_id"`
	User   User   `json:"user"`
}

type User struct {
	NodeID string `json:"node_id"`
}

// PRFromEnv returns the PR by parsing it from "GITHUB_PR" env var or an error.
func PRFromEnv() (PR, error) {
	const prEnv = "GITHUB_PR"
	prJSON, ok := os.LookupEnv(prEnv)
	if !ok || strings.TrimSpace(prJSON) == "" {
		return PR{}, errors.New("env variable not set", z.Str("var", prEnv))
	}

	var pr PR
	if err := json.Unmarshal([]byte(prJSON), &pr); err != nil {
		return PR{}, errors.Wrap(err, "unmarshal PR body")
	}

	if pr.Title == "" || pr.Body == "" || pr.NodeID == "" {
		return PR{}, errors.New("pr field not set")
	}

	return pr, nil
}

// track adds a PR without a ticket to the GitHub project board of the organization. It sets size as 1, iteration as current and status as done.
func track(ctx context.Context, ghToken string, pr PR, organization string, projectNumber int) error {
	ok := shouldTrack(pr)
	if !ok {
		log.Println("pr doesn't need to be tracked")
		return nil
	}

	client := gh.NewClient(oauth2.NewClient(ctx,
		oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: ghToken,
		}),
	))

	// Step 1: Get project data
	data, err := getProjectData(ctx, client, organization, projectNumber)
	if err != nil {
		return errors.Wrap(err, "failed to get project data")
	}

	// Step 2: Add PR to project board
	itemID, err := addProjectItem(ctx, client, data.projectID, pr.NodeID)
	if err != nil {
		return errors.Wrap(err, "failed to add to project")
	}

	// Step 3: Set size, status and sprint iteration fields
	if err := setStatus(ctx, client, data.projectID, itemID, data.statusFieldID, data.doneOptionID); err != nil {
		return errors.Wrap(err, "set status")
	}

	if err := setSprint(ctx, client, data.projectID, itemID, data.sprintFieldID, data.currIterationID); err != nil {
		return errors.Wrap(err, "set sprint")
	}

	if err := setSize(ctx, client, data.projectID, itemID, data.sizeFieldID, 1); err != nil {
		return errors.Wrap(err, "set size")
	}

	// Step 4: Assign PR to author
	if err := assignPR(ctx, client, pr.NodeID, pr.User.NodeID); err != nil {
		return errors.Wrap(err, "add assignee")
	}

	return nil
}

// getProjectData returns project data for the GitHub project.
func getProjectData(ctx context.Context, client *gh.Client, organization string, projectNumber int) (projectData, error) {
	query := new(projectQuery)
	variables := map[string]any{
		"org":    gh.String(organization),
		"number": gh.Int(projectNumber),
	}

	err := client.Query(ctx, &query, variables)
	if err != nil {
		return projectData{}, errors.Wrap(err, "query project data")
	}

	var (
		data    projectData
		project = query.Organization.ProjectV2
	)

	data.projectID = project.ID

	for _, node := range project.Fields.Nodes {
		// Sprint sizing
		if node.ProjectV2Field.Name == "Size" {
			data.sizeFieldID = node.ProjectV2Field.ID
		}

		statusField := node.ProjectV2SingleSelectField
		// PR status: https://docs.github.com/en/graphql/reference/objects#projectv2singleselectfield
		if statusField.Name == "Status" {
			data.statusFieldID = statusField.ID

			for _, opt := range statusField.Options {
				if opt.Name == "Done" {
					data.doneOptionID = opt.ID
				}
			}
		}

		sprintField := node.ProjectV2IterationField
		// sprint iteration: https://docs.github.com/en/graphql/reference/objects#projectv2iterationfielditeration
		if sprintField.Name == "Sprint" {
			data.sprintFieldID = sprintField.ID

			for _, iter := range sprintField.Configuration.Iterations {
				startDate, err := time.Parse("2006-01-02", iter.StartDate)
				if err != nil {
					return projectData{}, errors.Wrap(err, "parse date")
				}

				endDate := startDate.AddDate(0, 0, iter.Duration)

				currSprint := time.Now().After(startDate) && time.Now().Before(endDate)
				if currSprint {
					data.currIterationID = iter.ID
					// Get the earliest current sprint
					break
				}
			}
		}
	}

	if data.projectID == nil || data.statusFieldID == nil || data.doneOptionID == "" || data.sizeFieldID == nil || data.sprintFieldID == nil || data.currIterationID == nil {
		return projectData{}, errors.New("projectData field absent", z.Any("data", data))
	}

	return data, nil
}

// addProjectItem adds an item (issue/PR) to the GitHub project board and returns the ID of the added item. It doesn't set any of the item's fields.
func addProjectItem(ctx context.Context, client *gh.Client, projectID gh.ID, contentID string) (gh.ID, error) {
	m := new(addItemMutation)
	input := AddProjectV2ItemByIdInput{
		ContentID: contentID,
		ProjectID: projectID,
	}

	err := client.Mutate(ctx, m, input, nil)
	if err != nil {
		return nil, err
	}

	return m.AddProjectV2ItemByID.Item.ID, nil
}

// assignPR sets the assignee field (ex: 1, 2 etc.) of the project item.
func assignPR(ctx context.Context, client *gh.Client, prID, userID gh.ID) error {
	m := new(addAssigneesToAssignable)
	input := AddAssigneesToAssignableInput{
		AssignableID: prID,
		AssigneeIDs:  []gh.ID{userID},
	}

	err := client.Mutate(ctx, m, input, nil)

	return err
}

// setSize sets the size field (ex: 1, 2 etc.) of the project item.
func setSize(ctx context.Context, client *gh.Client, projectID, itemID, sizeFieldID gh.ID, size gh.Float) error {
	m := new(setFieldMutation)
	input := UpdateProjectV2ItemFieldValueInput{
		ProjectID: projectID,
		ItemID:    itemID,
		FieldID:   sizeFieldID,
		Value: ProjectV2FieldValue{
			Number: size,
		},
	}

	err := client.Mutate(ctx, m, input, nil)

	return err
}

// setStatus sets the status field (ex: "Done", "In Progress" etc.) of the project item.
func setStatus(ctx context.Context, client *gh.Client, projectID, itemID, statusFieldID gh.ID, doneOptionID gh.String) error {
	m := new(setFieldMutation)
	input := UpdateProjectV2ItemFieldValueInput{
		ProjectID: projectID,
		ItemID:    itemID,
		FieldID:   statusFieldID,
		Value: ProjectV2FieldValue{
			SingleSelectOptionID: doneOptionID,
		},
	}

	err := client.Mutate(ctx, m, input, nil)

	return err
}

// setSprint sets the sprint field (ex: "Sprint 1", "Sprint 4" etc.) of the project item.
func setSprint(ctx context.Context, client *gh.Client, projectID, itemID, sprintFieldID, iterationID gh.ID) error {
	m := new(setFieldMutation)
	input := UpdateProjectV2ItemFieldValueInput{
		ProjectID: projectID,
		ItemID:    itemID,
		FieldID:   sprintFieldID,
		Value: ProjectV2FieldValue{
			IterationID: iterationID,
		},
	}

	err := client.Mutate(ctx, m, input, nil)

	return err
}

// shouldTrack returns true if the ticket is "none" for the PR and returns false otherwise. It doesn't verify the PR body
// and assumes that PR verification step is already complete. Only call shouldTrack after verify.
func shouldTrack(pr PR) bool {
	// Skip dependabot PRs.
	if strings.Contains(pr.Title, "build(deps)") && strings.Contains(pr.Body, "dependabot") {
		return false
	}

	const ticketTag = "ticket:"

	for _, line := range strings.Split(pr.Body, "\n") {
		if !strings.HasPrefix(line, ticketTag) {
			continue
		}

		ticket := strings.TrimSpace(strings.TrimPrefix(line, ticketTag))
		if ticket == "none" {
			return true
		}
	}

	return false
}
