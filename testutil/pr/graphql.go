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
package pr

import gh "github.com/shurcooL/githubv4"

// projectV2FieldValue is a value to use in updateProjectV2ItemFieldValueInput.
// https://docs.github.com/en/graphql/reference/input-objects#projectv2fieldvalue
type projectV2FieldValue struct {
	IterationID          gh.ID     `json:"iterationId,omitempty"`
	Number               gh.Float  `json:"number,omitempty"`
	SingleSelectOptionID gh.String `json:"singleSelectOptionId,omitempty"`
}

// updateProjectV2ItemFieldValueInput is an input for UpdateProjectV2ItemFieldValue.
// https://docs.github.com/en/graphql/reference/input-objects#updateprojectv2itemfieldvalueinput
type updateProjectV2ItemFieldValueInput struct {
	FieldID   gh.ID               `json:"fieldId"`
	ItemID    gh.ID               `json:"itemId"`
	ProjectID gh.ID               `json:"projectId"`
	Value     projectV2FieldValue `json:"value"`
}

// addProjectV2ItemByIdInput is an input for AddProjectV2ItemById.
// https://docs.github.com/en/graphql/reference/input-objects#addprojectv2itembyidinput
type addProjectV2ItemByIdInput struct { //nolint:revive,stylecheck
	// The ID of the Project to add the item to. (Required.)
	ProjectID gh.ID `json:"projectId"`
	// The content id of the item (Issue or PullRequest). (Required.)
	ContentID gh.ID `json:"contentId"`
}

// projectQuery represents the graphql response for querying a GitHub project. Note that we query only for the first 25 fields.
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

// addItemMutation adds the item to the project board.
// https://docs.github.com/en/graphql/reference/mutations#addprojectv2itembyid
type addItemMutation struct {
	AddProjectV2ItemByID struct {
		Item struct {
			ID gh.ID `graphql:"id"`
		} `graphql:"item"`
	} `graphql:"addProjectV2ItemById(input: $input)"`
}

// setSizeMutation sets the size field of the project item.
// https://docs.github.com/en/graphql/reference/mutations#updateprojectv2itemfieldvalue
type setSizeMutation struct {
	UpdateProjectV2ItemFieldValue struct {
		ProjectV2Item struct {
			ID gh.ID `graphql:"id"`
		} `graphql:"projectV2Item"`
	} `graphql:"updateProjectV2ItemFieldValue(input: $input)"`
}

// setStatusMutation sets the status (ex: "Done", "In Progress" etc.) field of the project item.
// https://docs.github.com/en/graphql/reference/mutations#updateprojectv2itemfieldvalue
type setStatusMutation struct {
	UpdateProjectV2ItemFieldValue struct {
		ProjectV2Item struct {
			ID gh.ID `graphql:"id"`
		} `graphql:"projectV2Item"`
	} `graphql:"updateProjectV2ItemFieldValue(input: $input)"`
}

// setSprintMutation sets the sprint (ex: "Sprint 1", "Sprint 4" etc.) field of the project item.
// https://docs.github.com/en/graphql/reference/mutations#updateprojectv2itemfieldvalue
type setSprintMutation struct {
	UpdateProjectV2ItemFieldValue struct {
		ProjectV2Item struct {
			ID gh.ID `graphql:"id"`
		} `graphql:"projectV2Item"`
	} `graphql:"updateProjectV2ItemFieldValue(input: $input)"`
}
