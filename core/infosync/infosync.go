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
	"fmt"
	"sync"

	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/priority"
)

const (
	topicVersion  = "version"
	topicProtocol = "protocol"
)

// New returns a new infosync component.
func New(prioritiser *priority.Component, versions []string, protocols []protocol.ID) *Component {
	// Add a mock alpha protocol if alpha features enabled iot to test infosync in prod.
	// TODO(corver): Remove this once we have an actual use case.
	if featureset.Enabled(featureset.MockAlpha) {
		protocols = append(protocols, "/charon/mock_alpha/1.0.0")
	}

	c := &Component{
		prioritiser: prioritiser,
		versions:    versions,
		protocols:   protocols,
	}

	prioritiser.Subscribe(func(ctx context.Context, duty core.Duty, results []priority.TopicResult) error {
		res := result{slot: duty.Slot}
		var fields []z.Field
		for _, result := range results {
			fields = append(fields, z.Any(result.Topic, result.Priorities))

			for _, prio := range result.PrioritiesOnly() {
				switch result.Topic {
				case topicVersion:
					res.versions = append(res.versions, prio)
				case topicProtocol:
					res.protocols = append(res.protocols, protocol.ID(prio))
				}
			}
		}

		log.Debug(ctx, "Infosync completed", fields...)
		c.addResult(res)

		return nil
	})

	return c
}

type Component struct {
	prioritiser *priority.Component
	versions    []string
	protocols   []protocol.ID

	mu      sync.Mutex
	results []result
}

// Protocols returns the latest cluster wide supported protocols before the slot.
// It returns the local protocols if no results before the slot are available.
func (c *Component) Protocols(slot int64) []protocol.ID {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp := c.protocols // Start with local protocols.

	for _, result := range c.results {
		if result.slot > slot {
			break
		}

		resp = result.protocols
	}

	return resp
}

func (c *Component) addResult(result result) {
	c.mu.Lock()
	defer c.mu.Unlock()

	last := len(c.results) - 1
	if last >= 0 && c.results[last].Equal(result) {
		// Identical to previous, so don't add.
		return
	}

	c.results = append(c.results, result)
}

func (c *Component) Trigger(ctx context.Context, slot int64) error {
	return c.prioritiser.Prioritise(ctx, core.NewInfoSyncDuty(slot),
		priority.TopicProposal{
			Topic:      topicVersion,
			Priorities: c.versions,
		},
		priority.TopicProposal{
			Topic:      topicProtocol,
			Priorities: protocolsToStrings(c.protocols),
		})
}

// protocolsToStrings returns the protocols as strings.
func protocolsToStrings(features []protocol.ID) []string {
	var resp []string
	for _, feature := range features {
		resp = append(resp, string(feature))
	}

	return resp
}

// result is a cluster-wide agreed-upon infosync result.
type result struct {
	slot      int64
	versions  []string
	protocols []protocol.ID
}

// Equal returns true if the results are equal.
func (x result) Equal(y result) bool {
	return x.slot == y.slot &&
		fmt.Sprint(x.versions) == fmt.Sprint(y.versions) &&
		fmt.Sprint(x.protocols) == fmt.Sprint(y.protocols)
}
