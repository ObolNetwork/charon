// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package infosync provides a simple use-case of the priority protocol that prioritises cluster supported versions.
package infosync

import (
	"context"
	"fmt"
	"sync"

	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/priority"
)

const (
	topicVersion  = "version"
	topicProtocol = "protocol"
	topicProposal = "proposal"

	// maxResults limits the number of results to keep.
	maxResults = 100

	TopicProtocol = topicProtocol
)

// New returns a new infosync component.
func New(prioritiser *priority.Component, versions []version.SemVer, protocols []protocol.ID,
	proposals []core.ProposalType,
) *Component {
	// Add a mock alpha protocol if alpha features enabled in order to test infosync in prod.
	// TODO(corver): Remove this once we have an actual use case.
	if featureset.Enabled(featureset.MockAlpha) {
		protocols = append(protocols, "/charon/mock_alpha/1.0.0")
	}

	c := &Component{
		prioritiser: prioritiser,
		versions:    versions,
		protocols:   protocols,
		proposals:   proposals,
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
				case topicProposal:
					res.proposals = append(res.proposals, core.ProposalType(prio))
				default:
				}
			}
		}

		log.Debug(ctx, "Infosync completed", fields...)

		if len(res.versions) > 0 {
			c.addResult(res)
		}

		return nil
	})

	return c
}

type Component struct {
	prioritiser *priority.Component
	versions    []version.SemVer
	protocols   []protocol.ID
	proposals   []core.ProposalType

	mu      sync.Mutex
	results []result
}

// Protocols returns the latest cluster wide supported protocols before the slot.
// It returns the local protocols if no results before the slot are available.
func (c *Component) Protocols(slot uint64) []protocol.ID {
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

// Proposals returns the latest cluster wide supported proposal types before the slot.
// It returns the default "full" proposal type if no results before the slot are available.
func (c *Component) Proposals(slot uint64) []core.ProposalType {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp := []core.ProposalType{core.ProposalTypeFull} // Default to "full" proposals.

	for _, result := range c.results {
		if result.slot > slot {
			break
		}

		resp = result.proposals
	}

	return resp
}

// addResult adds the result to the results if it is different from the last result.
func (c *Component) addResult(result result) {
	c.mu.Lock()
	defer c.mu.Unlock()

	last := len(c.results) - 1
	if last >= 0 && c.results[last].Equal(result) {
		// Identical to previous, so don't add.
		return
	}

	c.results = append(c.results, result)

	if len(c.results) >= maxResults {
		c.results = c.results[1:]
	}
}

func (c *Component) Trigger(ctx context.Context, slot uint64) error {
	return c.prioritiser.Prioritise(ctx, core.NewInfoSyncDuty(slot),
		priority.TopicProposal{
			Topic:      topicVersion,
			Priorities: versionsToStrings(c.versions),
		},
		priority.TopicProposal{
			Topic:      topicProtocol,
			Priorities: protocolsToStrings(c.protocols),
		},
		priority.TopicProposal{
			Topic:      topicProposal,
			Priorities: proposalsToStrings(c.proposals),
		})
}

// versionsToStrings returns the versions as strings.
func versionsToStrings(versions []version.SemVer) []string {
	var resp []string
	for _, version := range versions {
		resp = append(resp, version.String())
	}

	return resp
}

// protocolsToStrings returns the protocols as strings.
func protocolsToStrings(features []protocol.ID) []string {
	var resp []string
	for _, feature := range features {
		resp = append(resp, string(feature))
	}

	return resp
}

// proposalsToStrings returns the protocols as strings.
func proposalsToStrings(proposals []core.ProposalType) []string {
	var resp []string
	for _, proposal := range proposals {
		resp = append(resp, string(proposal))
	}

	return resp
}

// result is a cluster-wide agreed-upon infosync result.
type result struct {
	slot      uint64
	versions  []string
	protocols []protocol.ID
	proposals []core.ProposalType
}

// Equal returns true if the results are equal.
func (x result) Equal(y result) bool {
	return x.slot == y.slot &&
		fmt.Sprint(x.versions) == fmt.Sprint(y.versions) &&
		fmt.Sprint(x.protocols) == fmt.Sprint(y.protocols) &&
		fmt.Sprint(x.proposals) == fmt.Sprint(y.proposals)
}
