// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

import (
	"context"
	"fmt"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestDelayFuncSpecOffsets(t *testing.T) {
	// The expected submission time of a duty is its spec-defined offset into the slot, so the
	// gloas deadlines report a larger delay than the pre-gloas deadlines for the same broadcast.
	preGloas, err := beaconmock.New(t.Context())
	require.NoError(t, err)

	gloas, err := beaconmock.New(t.Context(), beaconmock.WithSpecOverride("GLOAS_FORK_EPOCH", "0"))
	require.NoError(t, err)

	preGloasFunc, err := newDelayFunc(t.Context(), preGloas, forkScheduleFunc(t, preGloas))
	require.NoError(t, err)

	gloasFunc, err := newDelayFunc(t.Context(), gloas, forkScheduleFunc(t, gloas))
	require.NoError(t, err)

	tests := []struct {
		dutyType core.DutyType
		expect   time.Duration // How much earlier the gloas deadline is, for a 12s slot duration.
	}{
		{dutyType: core.DutyAttester, expect: time.Second},       // 4s to 3s
		{dutyType: core.DutyAggregator, expect: 2 * time.Second}, // 8s to 6s
		{dutyType: core.DutySyncContribution, expect: 2 * time.Second},
		{dutyType: core.DutyProposer, expect: 0},    // Proposals are due at the start of the slot.
		{dutyType: core.DutySyncMessage, expect: 0}, // Charon reports sync messages from the start of the slot.
	}

	for _, test := range tests {
		t.Run(test.dutyType.String(), func(t *testing.T) {
			const slot = 100

			gloasDelay := gloasFunc(slot, test.dutyType)
			preGloasDelay := preGloasFunc(slot, test.dutyType)

			require.InDelta(t, test.expect, gloasDelay-preGloasDelay, float64(50*time.Millisecond))
		})
	}
}

func TestDelayFuncProposerPreferences(t *testing.T) {
	// Proposer preferences for a proposal slot in epoch E are anchored to the start of epoch
	// E-1, the earliest time they can be computed. So relative to the proposal slot start
	// (the proposer duty anchor), the reported delay is larger by a full epoch plus the
	// slots into the proposal epoch.
	bmock, err := beaconmock.New(t.Context(), beaconmock.WithSpecOverride("GLOAS_FORK_EPOCH", "0"))
	require.NoError(t, err)

	delayFunc, err := newDelayFunc(t.Context(), bmock, forkScheduleFunc(t, bmock))
	require.NoError(t, err)

	slotDuration, slotsPerEpoch, err := eth2wrap.FetchSlotsConfig(t.Context(), bmock)
	require.NoError(t, err)

	const slot = 100

	expect := time.Duration(slot%slotsPerEpoch+slotsPerEpoch) * slotDuration

	diff := delayFunc(slot, core.DutyProposerPreferences) - delayFunc(slot, core.DutyProposer)
	require.InDelta(t, expect, diff, float64(50*time.Millisecond))
}

// forkScheduleFunc returns a function providing the fork schedule of the beacon node.
func forkScheduleFunc(t *testing.T, eth2Cl eth2wrap.Client) func() eth2wrap.ForkForkSchedule {
	t.Helper()

	forkSchedule, err := eth2wrap.FetchForkConfig(t.Context(), eth2Cl)
	require.NoError(t, err)

	return func() eth2wrap.ForkForkSchedule { return forkSchedule }
}

func TestBroadcastGloasProposal(t *testing.T) {
	const configured = "https://builder-a.example.com"

	builderConfig := &gloas.BuilderConfig{
		Builders: []*gloas.BuilderEntry{{URL: []byte(configured)}},
	}

	tests := []struct {
		name        string
		builderURL  string // Of the agreed proposal.
		noAgreed    bool   // The agreed proposal can't be found.
		slowAgreed  bool   // The agreed proposal lookup doesn't return before its deadline.
		selfBuilt   bool
		noBid       bool // The signed block's bid can't be read.
		wantURL     string
		wantSource  string
		wantBuilder string
		wantCounted bool
	}{
		{name: "p2p bid, no url", wantSource: core.BuilderSourceP2P, wantCounted: true},
		{name: "configured url forwarded", builderURL: configured, wantURL: configured, wantSource: core.BuilderSourceDirect, wantBuilder: "builder-a.example.com", wantCounted: true},
		// The agreed URL is forwarded as the beacon node spelled it, e.g. with a trailing slash.
		{name: "beacon node spelling forwarded", builderURL: configured + "/", wantURL: configured + "/", wantSource: core.BuilderSourceDirect, wantBuilder: "builder-a.example.com", wantCounted: true},
		{name: "unconfigured url forwarded", builderURL: "https://other.example.com", wantURL: "https://other.example.com", wantSource: core.BuilderSourceDirect, wantBuilder: "other.example.com", wantCounted: true},
		{name: "self-built with url ignored", builderURL: configured, selfBuilt: true, wantSource: core.BuilderSourceLocal, wantCounted: true},
		// Without the agreed proposal a builder bid can't be told apart, so it isn't counted.
		{name: "agreed proposal missing", builderURL: configured, noAgreed: true, wantSource: builderSourceUnknown},
		{name: "agreed proposal lookup times out", builderURL: configured, slowAgreed: true, wantSource: builderSourceUnknown},
		// Metadata never stops a block from being published.
		{name: "unreadable bid still published", noBid: true, wantSource: builderSourceUnknown},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mock, err := beaconmock.New(t.Context())
			require.NoError(t, err)

			proposal := testutil.RandomGloasCoreVersionedSignedProposal()

			bid := proposal.Gloas.Message.Body.SignedExecutionPayloadBid.Message
			bid.BuilderIndex = 7

			if test.selfBuilt {
				bid.BuilderIndex = core.BuilderIndexSelfBuild
			}

			if test.noBid {
				proposal.Gloas.Message.Body.SignedExecutionPayloadBid = nil
			}

			var submitted *eth2api.SubmitProposalOpts

			mock.SubmitProposalFunc = func(_ context.Context, opts *eth2api.SubmitProposalOpts) error {
				submitted = opts

				return nil
			}

			bcaster, err := New(t.Context(), mock, func() eth2wrap.ForkForkSchedule { return nil }, WithBuilderConfig(builderConfig))
			require.NoError(t, err)

			// The builder URL comes from this node's own agreed proposal, never from the partials.
			bcaster.RegisterAwaitVersionedProposal(func(ctx context.Context, slot uint64) (core.VersionedProposal, error) {
				require.Equal(t, uint64(1), slot)
				require.False(t, test.selfBuilt, "a self-built proposal has no builder URL to look up")
				require.False(t, test.noBid, "a proposal without a bid has no builder URL to look up")

				if test.noAgreed {
					return core.VersionedProposal{}, errors.New("no agreed proposal")
				}

				if test.slowAgreed {
					<-ctx.Done()
					return core.VersionedProposal{}, ctx.Err()
				}

				agreed, err := core.NewVersionedEPBSProposal(&eth2api.VersionedEPBSProposal{
					Version: proposal.Version,
					Gloas:   proposal.Gloas.Message,
				})
				require.NoError(t, err)

				agreed.BuilderURL = test.builderURL

				return agreed, nil
			})

			counter := proposalSourceCounter.WithLabelValues(test.wantSource, test.wantBuilder)
			before := promtest.ToFloat64(counter)

			var logs zaptest.Buffer
			log.InitLogfmtForT(t, &logs)

			pubkey := testutil.RandomCorePubKey(t)
			err = bcaster.Broadcast(t.Context(), core.NewProposerDuty(1), core.SignedDataSet{pubkey: proposal})
			require.NoError(t, err)

			// The log line carries the same fields for every builder source.
			require.Contains(t, logs.String(), "Successfully submitted block proposal to beacon node")
			require.Contains(t, logs.String(), "builder_source="+test.wantSource)
			require.Contains(t, logs.String(), "builder_index=")
			require.Contains(t, logs.String(), "builder_url=")
			require.Contains(t, logs.String(), fmt.Sprintf("builder_url_forwarded=%t", test.wantURL != ""))

			if test.wantURL == "" && test.wantSource != core.BuilderSourceDirect {
				require.NotContains(t, logs.String(), "example.com", "builder_url only logged for direct bids")
			}

			require.NotNil(t, submitted)
			require.Equal(t, proposal.Gloas, submitted.Proposal.Gloas)
			require.Equal(t, test.wantURL, submitted.BuilderURL)

			want := before
			if test.wantCounted {
				want++
			}

			require.InDelta(t, want, promtest.ToFloat64(counter), 0)
		})
	}
}
