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

// Package infosync provides a simple use-case of the priority protocol that prioritises cluster supported versions.
package infosync

import (
	"context"
	"strings"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/priority"
)

const topicVersion = "version"

// New returns a new infosync component.
func New(prioritiser *priority.Component, versions []string) *Component {
	prioritiser.Subscribe(func(ctx context.Context, duty core.Duty, results []priority.TopicResult) error {
		resultType := resultEmpty
		for _, result := range results {
			log.Debug(ctx, "Infosync completed", z.Any(result.Topic, result.Priorities))

			if result.Topic != topicVersion {
				continue
			}

			if len(result.Priorities) == 0 {
				resultType = resultEmpty
			} else if strings.Join(result.PrioritiesOnly(), ",") == strings.Join(versions, ",") {
				resultType = resultOwn
			} else {
				resultType = resultOther
			}
		}

		completeTotal.WithLabelValues(resultType).Inc()

		return nil
	})

	return &Component{
		prioritiser: prioritiser,
		versions:    versions,
	}
}

type Component struct {
	prioritiser *priority.Component
	versions    []string
}

func (c *Component) Trigger(ctx context.Context, slot int64) error {
	return c.prioritiser.Prioritise(ctx, core.NewInfoSyncDuty(slot), priority.TopicProposal{
		Topic:      topicVersion,
		Priorities: c.versions,
	})
}
