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

//nolint:wrapcheck,revive,cyclop,forbidigo, exhaustruct
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"

	"github.com/obolnetwork/charon/app/errors"
)

const (
	organization  = "twin-devs"
	projectNumber = githubv4.Int(1)
)

// https://docs.github.com/en/graphql/reference/input-objects#projectv2fieldvalue
type ProjectV2FieldValue struct {
	Date                 githubv4.Date   `json:"date,omitempty"`
	IterationID          githubv4.ID     `json:"iterationId,omitempty"`
	Number               githubv4.Float  `json:"number,omitempty"`
	SingleSelectOptionID githubv4.String `json:"singleSelectOptionId,omitempty"`
	Text                 githubv4.String `json:"text,omitempty"`
}

// https://docs.github.com/en/graphql/reference/input-objects#updateprojectv2itemfieldvalueinput
type UpdateProjectV2ItemFieldValueInput struct {
	ClientMutationID githubv4.String     `json:"clientMutationId,omitempty"`
	FieldID          githubv4.ID         `json:"fieldId"`
	ItemID           githubv4.ID         `json:"itemId"`
	ProjectID        githubv4.ID         `json:"projectId"`
	Value            ProjectV2FieldValue `json:"value"`
}

// https://docs.github.com/en/graphql/reference/input-objects#addprojectv2itembyidinput
type AddProjectV2ItemByIDInput struct {
	// The ID of the Project to add the item to. (Required.)
	ProjectID githubv4.ID `json:"projectId"`
	// The content id of the item (Issue or PullRequest). (Required.)
	ContentID githubv4.ID `json:"contentId"`

	// A unique identifier for the client performing the mutation. (Optional.)
	ClientMutationID *githubv4.String `json:"clientMutationId,omitempty"`
}

type config struct {
	projectID       githubv4.ID
	statusFieldID   githubv4.ID
	doneOptionID    githubv4.String
	sizeFieldID     githubv4.ID
	sprintFieldID   githubv4.ID
	currIterationID githubv4.ID
}

func main() {
	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GH_TOKEN")},
	)

	httpClient := oauth2.NewClient(context.Background(), src)

	client := githubv4.NewClient(httpClient)

	// Step 1: Get project data
	conf, err := getProjectData(client, organization, projectNumber)
	if err != nil {
		fmt.Printf("failed to get project data: %s\n", err.Error())
		os.Exit(1)
	}
	fmt.Println("config:", conf)

	// Step 2: Add PR to project
	itemID, err := addToProject(client, conf.projectID)
	if err != nil {
		fmt.Printf("failed to add to project: %s\n", err.Error())
	}
	fmt.Println("itemID", itemID)

	// Step 3: Set size, status and sprint iteration fields
	err = setFields(client, itemID, conf)
	if err != nil {
		fmt.Printf("failed to set fields: %s", err.Error())
	}
}

// setFields sets the size, status and sprint fields to the project item.
func setFields(client *githubv4.Client, itemID githubv4.ID, conf config) error {
	// https://docs.github.com/en/graphql/reference/mutations#updateprojectv2itemfieldvalue
	var mutateStatus struct {
		UpdateProjectV2ItemFieldValue struct {
			ProjectV2Item struct {
				ID githubv4.ID `graphql:"id"`
			} `graphql:"projectV2Item"`
		} `graphql:"updateProjectV2ItemFieldValue(input: $input)"`
	}

	inputStatus := UpdateProjectV2ItemFieldValueInput{
		ProjectID: conf.projectID,
		ItemID:    itemID,
		FieldID:   conf.statusFieldID,
		Value: ProjectV2FieldValue{
			SingleSelectOptionID: conf.doneOptionID,
		},
	}

	err := client.Mutate(context.Background(), &mutateStatus, inputStatus, nil)
	if err != nil {
		return errors.Wrap(err, "set status")
	}

	var mutateSprint struct {
		UpdateProjectV2ItemFieldValue struct {
			ProjectV2Item struct {
				ID githubv4.ID `graphql:"id"`
			} `graphql:"projectV2Item"`
		} `graphql:"updateProjectV2ItemFieldValue(input: $input)"`
	}

	inputSprint := UpdateProjectV2ItemFieldValueInput{
		ProjectID: conf.projectID,
		ItemID:    itemID,
		FieldID:   conf.sprintFieldID,
		Value: ProjectV2FieldValue{
			IterationID: conf.currIterationID,
		},
	}

	err = client.Mutate(context.Background(), &mutateSprint, inputSprint, nil)
	if err != nil {
		return errors.Wrap(err, "set sprint")
	}

	return nil
}

// addToProject adds the PR to the GitHub project board. It doesn't set any of the fields.
func addToProject(client *githubv4.Client, projectID githubv4.ID) (githubv4.ID, error) {
	prID, ok := os.LookupEnv("PR_ID")
	if !ok {
		return nil, fmt.Errorf("cannot find PR_ID in env")
	}

	var mutation struct {
		AddProjectV2ItemByID struct {
			Item struct {
				ID githubv4.ID `graphql:"id"`
			} `graphql:"item"`
		} `graphql:"addProjectV2ItemById(input: $input)"`
	}

	input := AddProjectV2ItemByIDInput{
		ContentID: prID,
		ProjectID: projectID,
	}

	err := client.Mutate(context.Background(), &mutation, input, nil)
	if err != nil {
		return nil, err
	}

	return mutation.AddProjectV2ItemByID.Item.ID, nil
}

func getProjectData(client *githubv4.Client, org string, projectNumber githubv4.Int) (config, error) {
	variables := map[string]interface{}{
		"org":    githubv4.String(org),
		"number": projectNumber,
	}

	// Note that we query for the first 25 fields.
	var query struct {
		Organization struct {
			ProjectV2 struct {
				ID     githubv4.ID `graphql:"id"`
				Fields struct {
					Nodes []struct {
						// For Size field
						ProjectV2Field struct {
							ID   githubv4.ID     `graphql:"id"`
							Name githubv4.String `graphql:"name"`
						} `graphql:"... on ProjectV2Field"`

						// For Status field
						ProjectV2SingleSelectField struct {
							ID      githubv4.ID     `graphql:"id"`
							Name    githubv4.String `graphql:"name"`
							Options []struct {
								ID   githubv4.String `graphql:"id"`
								Name githubv4.String `graphql:"name"`
							}
						} `graphql:"... on ProjectV2SingleSelectField"`

						// For Sprint field
						ProjectV2IterationField struct {
							ID            githubv4.ID     `graphql:"id"`
							Name          githubv4.String `graphql:"name"`
							Configuration struct {
								Iterations []struct {
									ID        githubv4.ID     `graphql:"id"`
									Title     githubv4.String `graphql:"title"`
									Duration  int             `graphql:"duration"`
									StartDate string          `graphql:"startDate"`
								} `graphql:"iterations"`
							} `graphql:"configuration"`
						} `graphql:"... on ProjectV2IterationField"`
					} `graphql:"nodes"`
				} `graphql:"fields(first:25)"`
			} `graphql:"projectV2(number: $number)"`
		} `graphql:"organization(login: $org)"`
	}

	err := client.Query(context.Background(), &query, variables)
	if err != nil {
		return config{}, err
	}

	var conf config

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

			for _, opt := range node.ProjectV2SingleSelectField.Options {
				if opt.Name == "Done" {
					conf.doneOptionID = opt.ID
				}

				fmt.Printf("status name: %s and id: %s\n", opt.Name, opt.ID)
			}
		}

		// sprint iteration: https://docs.github.com/en/graphql/reference/objects#projectv2iterationfielditeration
		if node.ProjectV2IterationField.Name == "Sprint" {
			conf.sprintFieldID = node.ProjectV2IterationField.ID

			for _, iter := range node.ProjectV2IterationField.Configuration.Iterations {
				layout := "2006-01-02"

				startDate, err := time.Parse(layout, iter.StartDate)
				if err != nil {
					fmt.Println("error", err.Error())
				}

				endDate := startDate.AddDate(0, 0, iter.Duration)

				currSprint := time.Now().Before(endDate)
				if currSprint {
					conf.currIterationID = iter.ID
				}
			}
		}
	}

	// Ensure none of the fields is nil.

	return conf, nil
}
