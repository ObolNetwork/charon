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
	"log"
	"os"

	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

const (
	organization  = "twin-devs"
	projectNumber = 1
)

func main() {
	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GH_TOKEN")},
	)

	httpClient := oauth2.NewClient(context.Background(), src)

	client := githubv4.NewClient(httpClient)
	if err := getProjectData(client, organization, projectNumber); err != nil {
		fmt.Printf("failed to get project data: %s\n", err.Error())
		os.Exit(1)
	}

	log.Fatal("success at last")
}

func getProjectData(client *githubv4.Client, org string, projectNumber int) error {
	variables := map[string]interface{}{
		"org":    githubv4.String(org),
		"number": githubv4.Int(projectNumber),
	}

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
								ID   githubv4.ID     `graphql:"id"`
								Name githubv4.String `graphql:"name"`
							}
						} `graphql:"... on ProjectV2SingleSelectField"`

						// For Sprint field
						ProjectV2IterationField struct {
							ID            githubv4.ID     `graphql:"id"`
							Name          githubv4.String `graphql:"name"`
							Configuration struct {
								Iterations struct {
									ID    githubv4.ID     `graphql:"id"`
									Title githubv4.String `graphql:"title"`
								} `graphql:"iterations"`
							} `graphql:"configuration"`
						} `graphql:"... on ProjectV2IterationField"`
					} `graphql:"nodes"`
				} `graphql:"fields(first:10)"`
			} `graphql:"projectV2(number: $number)"`
		} `graphql:"organization(login: $org)"`
	}

	err := client.Query(context.Background(), &query, variables)
	if err != nil {
		return err
	}

	var (
		projectID     githubv4.ID
		statusFieldID githubv4.ID
		doneOptionID  githubv4.ID
		sizeFieldID   githubv4.ID
		sprintFieldID githubv4.ID
	)

	projectID = query.Organization.ProjectV2.ID

	if len(query.Organization.ProjectV2.Fields.Nodes) == 0 {
		return fmt.Errorf("empty list of fields")
	}

	// Get status field id and done option id
	for _, node := range query.Organization.ProjectV2.Fields.Nodes {
		// Sprint sizing
		if node.ProjectV2Field.Name == "Size" {
			sizeFieldID = node.ProjectV2Field.ID
		}

		// PR status
		if node.ProjectV2SingleSelectField.Name == "Status" {
			statusFieldID = node.ProjectV2SingleSelectField.ID

			for _, opt := range node.ProjectV2SingleSelectField.Options {
				if opt.Name == "Done" {
					doneOptionID = opt.ID
				}
			}
		}

		fmt.Println("possible", node.ProjectV2IterationField.Name)

		// sprint iteration
		if node.ProjectV2IterationField.Name == "Sprint" {
			sprintFieldID = node.ProjectV2IterationField.ID
		}
	}

	fmt.Println("project id", projectID)
	fmt.Println("status field id", statusFieldID)
	fmt.Println("done option id", doneOptionID)
	fmt.Println("size field id", sizeFieldID)
	fmt.Println("sprint field id", sprintFieldID)

	return nil
}
