// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Command trackpr tracks a PR without a ticket and adds it to GitHub project board.
package main

import gh "github.com/shurcooL/githubv4"

// ProjectV2FieldValue is a value to use in UpdateProjectV2ItemFieldValueInput.
// https://docs.github.com/en/graphql/reference/input-objects#projectv2fieldvalue
type ProjectV2FieldValue struct {
	IterationID          gh.ID     `json:"iterationId,omitempty"`
	Number               gh.Float  `json:"number,omitempty"`
	SingleSelectOptionID gh.String `json:"singleSelectOptionId,omitempty"`
}

// UpdateProjectV2ItemFieldValueInput is an input for UpdateProjectV2ItemFieldValue.
// https://docs.github.com/en/graphql/reference/input-objects#updateprojectv2itemfieldvalueinput
type UpdateProjectV2ItemFieldValueInput struct {
	FieldID   gh.ID               `json:"fieldId"`
	ItemID    gh.ID               `json:"itemId"`
	ProjectID gh.ID               `json:"projectId"`
	Value     ProjectV2FieldValue `json:"value"`
}

// AddProjectV2ItemByIdInput is an input for AddProjectV2ItemById.
// https://docs.github.com/en/graphql/reference/input-objects#addprojectv2itembyidinput
type AddProjectV2ItemByIdInput struct { //nolint:revive,stylecheck
	// The ID of the Project to add the item to. (Required.)
	ProjectID gh.ID `json:"projectId"`
	// The content id of the item (Issue or PullRequest). (Required.)
	ContentID gh.ID `json:"contentId"`
}

// AddAssigneesToAssignableInput is an input for AddAssigneesToAssignable.
// https://docs.github.com/en/graphql/reference/input-objects#addassigneestoassignableinput
type AddAssigneesToAssignableInput struct {
	// The id of the assignable object to add assignees to. (Required.)
	AssignableID gh.ID `json:"assignableId"`
	// The id of users to add as assignees. (Required.)
	AssigneeIDs []gh.ID `json:"assigneeIds"`
}

// projectQuery represents the graphql response when querying GitHub graphql API for a project. Note that we query only for the first 25 fields.
// https://docs.github.com/en/graphql/reference/queries#organization
type projectQuery struct {
	Organization struct {
		ProjectV2 struct {
			ID     gh.ID `graphql:"id"`
			Fields struct {
				Nodes []struct {
					// For Size field
					ProjectV2Field struct {
						ID   gh.ID     `graphql:"id"`
						Name gh.String `graphql:"name"`
					} `graphql:"... on ProjectV2Field"`

					// For Status field
					ProjectV2SingleSelectField struct {
						ID      gh.ID     `graphql:"id"`
						Name    gh.String `graphql:"name"`
						Options []struct {
							ID   gh.String `graphql:"id"`
							Name gh.String `graphql:"name"`
						}
					} `graphql:"... on ProjectV2SingleSelectField"`

					// For Sprint field
					ProjectV2IterationField struct {
						ID            gh.ID     `graphql:"id"`
						Name          gh.String `graphql:"name"`
						Configuration struct {
							Iterations []struct {
								ID        gh.ID     `graphql:"id"`
								Title     gh.String `graphql:"title"`
								Duration  int       `graphql:"duration"`
								StartDate string    `graphql:"startDate"`
							} `graphql:"iterations"`
						} `graphql:"configuration"`
					} `graphql:"... on ProjectV2IterationField"`
				} `graphql:"nodes"`
			} `graphql:"fields(first:25)"`
		} `graphql:"projectV2(number: $number)"`
	} `graphql:"organization(login: $org)"`
}

// addItemMutation adds item to the project board.
// https://docs.github.com/en/graphql/reference/mutations#addprojectv2itembyid
type addItemMutation struct {
	AddProjectV2ItemByID struct {
		Item struct {
			ID gh.ID `graphql:"id"`
		} `graphql:"item"`
	} `graphql:"addProjectV2ItemById(input: $input)"`
}

// setFieldMutation sets field of the project item.
// https://docs.github.com/en/graphql/reference/mutations#updateprojectv2itemfieldvalue
type setFieldMutation struct {
	UpdateProjectV2ItemFieldValue struct {
		ProjectV2Item struct {
			ID gh.ID `graphql:"id"`
		} `graphql:"projectV2Item"`
	} `graphql:"updateProjectV2ItemFieldValue(input: $input)"`
}

// addAssigneesToAssignable adds assignees to an assignable object..
// https://docs.github.com/en/graphql/reference/mutations#addassigneestoassignable
type addAssigneesToAssignable struct {
	UpdateProjectV2ItemFieldValue struct {
		Assignable struct {
			Assignees struct {
				TotalCount int `json:"totalCount"`
			} `graphql:"assignees"`
		} `graphql:"assignable"`
	} `graphql:"addAssigneesToAssignable(input: $input)"`
}
