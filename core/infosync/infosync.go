// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

	// minSyncContributionV2Version is the minimum charon version that supports the plural
	// SyncContributions encoding for DutySyncContribution. The cluster uses that
	// encoding once the quorum-agreed version topic includes at least this version,
	// i.e. once at least a threshold of peers advertise it (see SyncContributionsSupported).
	minSyncContributionV2Version = "v1.11"
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

		// Gate the plural SyncContributions encoding on the cluster-agreed versions
		// including one >= minSyncContributionV2Version. Since the version topic is quorum
		// filtered, this means at least threshold peers are on that version, which
		// is also the number needed to complete the duty; any smaller set of lagging
		// peers simply won't participate in sync contributions (they can't decode the
		// plural form) rather than blocking the duty.
		enabled, err := anyVersionAtLeast(res.versions, minSyncContributionV2Version)
		if err != nil {
			return err
		}

		c.addSyncContribResult(syncContribResult{slot: duty.Slot, enabled: enabled})

		return nil
	})

	return c
}

type Component struct {
	prioritiser *priority.Component
	versions    []version.SemVer
	protocols   []protocol.ID
	proposals   []core.ProposalType

	mu                 sync.Mutex
	results            []result
	syncContribResults []syncContribResult
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

// SyncContributionsSupported reports whether, per the latest info-sync round at
// or before the slot, the cluster-agreed (quorum-filtered) version topic includes
// a charon version >= minSyncContributionV2Version - i.e. whether at least a threshold of
// peers advertised it, and the cluster can use the plural SyncContributions
// encoding for DutySyncContribution. It defaults to false (the backwards-compatible
// single encoding) until a round has completed. Note this is a quorum signal, not
// all-peers: a sub-threshold set of lagging peers is not reflected here and will
// simply not participate in sync contributions rather than blocking them.
func (c *Component) SyncContributionsSupported(slot uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	var resp bool

	for _, result := range c.syncContribResults {
		if result.slot > slot {
			break
		}

		resp = result.enabled
	}

	return resp
}

// addSyncContribResult adds the sync-contribution gate result if it differs from the last.
func (c *Component) addSyncContribResult(result syncContribResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	last := len(c.syncContribResults) - 1
	if last >= 0 && c.syncContribResults[last].enabled == result.enabled {
		// Same decision as previous, so don't add (keep the earliest slot it became true/false).
		return
	}

	c.syncContribResults = append(c.syncContribResults, result)

	if len(c.syncContribResults) >= maxResults {
		c.syncContribResults = c.syncContribResults[1:]
	}
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

// syncContribResult is a cluster-wide agreed-upon decision, for a given slot, on
// whether a threshold of peers support the plural SyncContributions encoding.
type syncContribResult struct {
	slot    uint64
	enabled bool
}

// anyVersionAtLeast reports whether any of the cluster-agreed versions is at
// least minVer. The version topic is quorum filtered, so a version only appears
// here if at least threshold peers support it; the presence of one >= minVer
// therefore means at least threshold peers are on that version. Unparseable
// versions are ignored.
func anyVersionAtLeast(versions []string, minVer string) (bool, error) {
	minSemVer, err := version.Parse(minVer)
	if err != nil {
		return false, err
	}

	for _, v := range versions {
		semVer, err := version.Parse(v)
		if err != nil {
			continue // Ignore unparseable versions from peers.
		}

		if version.Compare(semVer, minSemVer) >= 0 {
			return true, nil
		}
	}

	return false, nil
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
