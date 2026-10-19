// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package fetcher

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"
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

func TestVerifyFeeRecipient(t *testing.T) {
	type testCase struct {
		name     string
		proposal core.VersionedProposal
		// match is a fee recipient address expected to verify without a warning.
		match string
	}

	const zeroAddr = "0x0000000000000000000000000000000000000000"

	gloasProposal := testutil.RandomGloasCoreVersionedEPBSProposalWithPayload()

	tests := []testCase{
		{
			name: "bellatrix",
			proposal: core.VersionedProposal{VersionedProposal: eth2api.VersionedProposal{
				Version:   eth2spec.DataVersionBellatrix,
				Blinded:   false,
				Bellatrix: testutil.RandomBellatrixBeaconBlock(),
			}},
			match: zeroAddr,
		},
		{
			name: "capella",
			proposal: core.VersionedProposal{VersionedProposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionCapella,
				Blinded: false,
				Capella: testutil.RandomCapellaBeaconBlock(),
			}},
			match: zeroAddr,
		},
		{
			name: "deneb",
			proposal: core.VersionedProposal{VersionedProposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionDeneb,
				Blinded: false,
				Deneb:   testutil.RandomDenebVersionedProposal().Deneb,
			}},
			match: zeroAddr,
		},
		{
			name: "electra",
			proposal: core.VersionedProposal{VersionedProposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionElectra,
				Blinded: false,
				Electra: testutil.RandomElectraVersionedProposal().Electra,
			}},
			match: zeroAddr,
		},
		{
			name: "fulu",
			proposal: core.VersionedProposal{VersionedProposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionFulu,
				Blinded: false,
				Fulu:    testutil.RandomFuluVersionedProposal().Fulu,
			}},
			match: zeroAddr,
		},
		{
			name:     "gloas",
			proposal: gloasProposal,
			match:    fmt.Sprintf("%#x", gloasProposal.EPBS.GloasContents.ExecutionPayloadEnvelope.Payload.FeeRecipient),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buf zaptest.Buffer
			log.InitLogfmtForT(t, &buf)

			verifyFeeRecipient(context.Background(), test.proposal, test.match)
			require.Empty(t, buf.String())

			verifyFeeRecipient(context.Background(), test.proposal, "0xdead")
			require.Contains(t, buf.String(), "Proposal with unexpected fee recipient address")
		})
	}
}

func TestFetchGloasAttester(t *testing.T) {
	const slot = 1

	var (
		t0          = time.Unix(1_000_000, 0)
		slotStart   = t0.Add(12 * time.Second)
		deadline    = slotStart.Add(3 * time.Second) // Attestations are due 1/4 into the slot from gloas.
		headRoot    = eth2p0.Root{0x01}
		otherRoot   = eth2p0.Root{0x02}
		errFetch    = errors.New("fetch error")
		pubkey      = testutil.RandomCorePubKey(t)
		attesterDef = core.NewAttesterDefinition(&eth2v1.AttesterDuty{Slot: slot, CommitteeLength: 1, CommitteesAtSlot: 1})
	)

	// setup returns a gloas fetcher at the start of the slot whose beacon node votes for the root
	// returned by rootFunc, along with a channel of fetched data sets.
	setup := func(t *testing.T, rootFunc func() (eth2p0.Root, error)) (*Fetcher, *clockwork.FakeClock, <-chan core.UnsignedDataSet) {
		t.Helper()

		bmock, err := beaconmock.New(t.Context(), beaconmock.WithGenesisTime(t0), beaconmock.WithSlotsPerEpoch(1))
		require.NoError(t, err)

		bmock.AttestationDataFunc = func(_ context.Context, reqSlot eth2p0.Slot, _ eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error) {
			root, err := rootFunc()
			if err != nil {
				return nil, err
			}

			data := testutil.RandomAttestationDataPhase0()
			data.Slot = reqSlot
			data.BeaconBlockRoot = root

			return data, nil
		}

		fetch, err := New(t.Context(), bmock, nil, false, &GraffitiBuilder{},
			func() eth2wrap.ForkForkSchedule { return eth2wrap.ForkForkSchedule{eth2wrap.Gloas: {Epoch: 0}} }, 1, &gloas.BuilderConfig{}, false)
		require.NoError(t, err)

		clock := clockwork.NewFakeClockAt(slotStart)
		fetch.clock = clock

		fetched := make(chan core.UnsignedDataSet, 1)

		fetch.Subscribe(func(_ context.Context, _ core.Duty, set core.UnsignedDataSet) error {
			fetched <- set
			return nil
		})

		return fetch, clock, fetched
	}

	// fetchAsync runs Fetch in the background, returning its error channel.
	fetchAsync := func(ctx context.Context, fetch *Fetcher) <-chan error {
		errCh := make(chan error, 1)

		go func() {
			errCh <- fetch.Fetch(ctx, core.NewAttesterDuty(slot), core.DutyDefinitionSet{pubkey: attesterDef})
		}()

		return errCh
	}

	requireFetched := func(t *testing.T, fetched <-chan core.UnsignedDataSet, errCh <-chan error, root eth2p0.Root) {
		t.Helper()

		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(time.Second):
			require.Fail(t, "attestation data not fetched")
		}

		set := <-fetched
		require.Equal(t, root, set[pubkey].(core.AttestationData).Data.BeaconBlockRoot)
	}

	requireWaiting := func(t *testing.T, fetched <-chan core.UnsignedDataSet) {
		t.Helper()

		select {
		case <-fetched:
			require.Fail(t, "fetched before a head event or the deadline")
		case <-time.After(10 * time.Millisecond):
		}
	}

	t.Run("head event before fetch is dropped", func(t *testing.T) {
		fetch, clock, fetched := setup(t, func() (eth2p0.Root, error) { return headRoot, nil })

		fetch.HandleHeadEvent(t.Context(), slot, headRoot, "bn")
		require.Empty(t, fetch.headEvents)

		errCh := fetchAsync(t.Context(), fetch)
		require.NoError(t, clock.BlockUntilContext(t.Context(), 1))
		requireWaiting(t, fetched)

		clock.Advance(deadline.Sub(slotStart))

		requireFetched(t, fetched, errCh, headRoot)
	})

	t.Run("head event while waiting", func(t *testing.T) {
		fetch, clock, fetched := setup(t, func() (eth2p0.Root, error) { return headRoot, nil })

		errCh := fetchAsync(t.Context(), fetch)
		require.NoError(t, clock.BlockUntilContext(t.Context(), 1))
		requireWaiting(t, fetched)

		fetch.HandleHeadEvent(t.Context(), slot, headRoot, "bn")

		requireFetched(t, fetched, errCh, headRoot)
		require.Empty(t, fetch.headEvents, "head events of the slot not removed after fetching")
	})

	t.Run("fallback deadline", func(t *testing.T) {
		fetch, clock, fetched := setup(t, func() (eth2p0.Root, error) { return otherRoot, nil })

		errCh := fetchAsync(t.Context(), fetch)
		require.NoError(t, clock.BlockUntilContext(t.Context(), 1))

		clock.Advance(deadline.Sub(slotStart) - time.Millisecond)
		requireWaiting(t, fetched)

		clock.Advance(time.Millisecond)

		requireFetched(t, fetched, errCh, otherRoot)
	})

	t.Run("fallback deadline is anchored to the slot start", func(t *testing.T) {
		fetch, clock, fetched := setup(t, func() (eth2p0.Root, error) { return otherRoot, nil })

		// Fetch starts late, 1s into the slot, yet still falls back 3s into the slot.
		clock.Advance(time.Second)

		errCh := fetchAsync(t.Context(), fetch)
		require.NoError(t, clock.BlockUntilContext(t.Context(), 1))

		clock.Advance(deadline.Sub(slotStart) - time.Second - time.Millisecond)
		requireWaiting(t, fetched)

		clock.Advance(time.Millisecond)

		requireFetched(t, fetched, errCh, otherRoot)
	})

	t.Run("fallback deadline already passed", func(t *testing.T) {
		fetch, clock, fetched := setup(t, func() (eth2p0.Root, error) { return otherRoot, nil })

		// Fetch starts after the deadline, e.g. upon a retry, and fetches immediately.
		clock.Advance(deadline.Sub(slotStart) + time.Second)

		requireFetched(t, fetched, fetchAsync(t.Context(), fetch), otherRoot)
	})

	t.Run("head root mismatch waits for the next head event", func(t *testing.T) {
		fetch, clock, fetched := setup(t, func() (eth2p0.Root, error) { return headRoot, nil })

		errCh := fetchAsync(t.Context(), fetch)
		require.NoError(t, clock.BlockUntilContext(t.Context(), 1))

		// The beacon node already moved on from the event's head, so the data isn't used.
		fetch.HandleHeadEvent(t.Context(), slot, otherRoot, "bn")
		requireWaiting(t, fetched)

		fetch.HandleHeadEvent(t.Context(), slot, headRoot, "bn")

		requireFetched(t, fetched, errCh, headRoot)
	})

	t.Run("head event beacon node error waits for the next head event", func(t *testing.T) {
		var calls int

		fetch, clock, fetched := setup(t, func() (eth2p0.Root, error) {
			calls++
			if calls == 1 {
				return eth2p0.Root{}, errFetch
			}

			return headRoot, nil
		})

		errCh := fetchAsync(t.Context(), fetch)
		require.NoError(t, clock.BlockUntilContext(t.Context(), 1))

		fetch.HandleHeadEvent(t.Context(), slot, headRoot, "bn1")
		requireWaiting(t, fetched)

		fetch.HandleHeadEvent(t.Context(), slot, headRoot, "bn2")

		requireFetched(t, fetched, errCh, headRoot)
		require.Equal(t, 2, calls)
	})

	t.Run("context cancelled", func(t *testing.T) {
		fetch, clock, _ := setup(t, func() (eth2p0.Root, error) { return headRoot, nil })

		ctx, cancel := context.WithCancel(t.Context())
		errCh := fetchAsync(ctx, fetch)

		require.NoError(t, clock.BlockUntilContext(t.Context(), 1))

		cancel()

		require.ErrorIs(t, <-errCh, context.Canceled)
		require.Empty(t, fetch.headEvents, "head events of the slot not removed after a failed fetch")
	})
}

// metadataClient adds response metadata to the mock's EPBS proposals.
type metadataClient struct {
	beaconmock.Mock

	metadata map[string]any
}

func (c metadataClient) EPBSProposal(ctx context.Context, opts *eth2api.EPBSProposalOpts) (*eth2api.Response[*eth2api.VersionedEPBSProposal], error) {
	resp, err := c.Mock.EPBSProposal(ctx, opts)
	if err != nil {
		return nil, err
	}

	resp.Metadata = c.metadata

	return resp, nil
}

func TestFetchEPBSBuilderSource(t *testing.T) {
	const (
		slot = 1
		url  = "https://Builder-Sepolia.nflaig.dev"
	)

	tests := []struct {
		name      string
		selfBuilt bool
		metadata  map[string]any
		wantURL   string
		wantGauge float64
		wantLabel string
	}{
		{name: "direct builder bid", metadata: map[string]any{"Eth-Builder-Url": url}, wantURL: url, wantGauge: proposalSourceDirect, wantLabel: "builder-sepolia.nflaig.dev"},
		{name: "lowercase header key", metadata: map[string]any{"eth-builder-url": url}, wantURL: url, wantGauge: proposalSourceDirect, wantLabel: "builder-sepolia.nflaig.dev"},
		{name: "p2p bid", wantGauge: proposalSourceBuilder},
		{name: "self-built ignores header", selfBuilt: true, metadata: map[string]any{"Eth-Builder-Url": url}, wantGauge: proposalSourceLocal},
		// A URL that can't be agreed would fail the proposal, so it is dropped.
		{name: "overlong url dropped", metadata: map[string]any{"Eth-Builder-Url": "https://" + strings.Repeat("a", core.MaxBuilderURLSize)}, wantGauge: proposalSourceBuilder},
	}

	const (
		bidValueGwei = 67_000_000
		executionWei = 67_000_000_500_000_000 // 67000000.5 gwei
		consensusWei = 40_000_000_000_000_000 // 40000000 gwei
	)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bmock, err := beaconmock.New(t.Context())
			require.NoError(t, err)

			bmock.EPBSProposalFunc = func(_ context.Context, opts *eth2api.EPBSProposalOpts) (*eth2api.VersionedEPBSProposal, error) {
				block := testutil.RandomGloasBeaconBlock()
				block.Slot = opts.Slot
				block.Body.RANDAOReveal = opts.RandaoReveal
				block.Body.SignedExecutionPayloadBid.Message.BuilderIndex = 7
				block.Body.SignedExecutionPayloadBid.Message.Value = bidValueGwei

				proposal := &eth2api.VersionedEPBSProposal{
					Version:        eth2spec.DataVersionGloas,
					Gloas:          block,
					ConsensusValue: big.NewInt(consensusWei),
					ExecutionValue: big.NewInt(executionWei),
				}

				// The client clears the execution value of self-built proposals.
				if tt.selfBuilt {
					block.Body.SignedExecutionPayloadBid.Message.BuilderIndex = core.BuilderIndexSelfBuild
					block.Body.SignedExecutionPayloadBid.Message.Value = 0
					proposal.ExecutionValue = nil
				}

				return proposal, nil
			}

			fetch, err := New(t.Context(), metadataClient{Mock: bmock, metadata: tt.metadata}, func(core.PubKey) string {
				return "0x0000000000000000000000000000000000000000"
			}, false, &GraffitiBuilder{},
				func() eth2wrap.ForkForkSchedule { return eth2wrap.ForkForkSchedule{eth2wrap.Gloas: {Epoch: 0}} }, 1, &gloas.BuilderConfig{}, false)
			require.NoError(t, err)

			randao := testutil.RandomCoreSignature()

			fetch.RegisterAggSigDB(func(context.Context, core.Duty, core.PubKey, core.AwaitOpts) (core.SignedData, error) {
				return randao, nil
			})

			pubkey := testutil.RandomCorePubKey(t)

			type sample struct{ sum, count float64 }

			valueOf := func(typ string) sample {
				return sample{
					sum:   promtest.ToFloat64(proposalValueSum.WithLabelValues(typ)),
					count: promtest.ToFloat64(proposalValueCount.WithLabelValues(typ)),
				}
			}

			before := map[string]sample{}
			for _, typ := range []string{proposalValueBid, proposalValueExecution, proposalValueConsensus} {
				before[typ] = valueOf(typ)
			}

			var logs zaptest.Buffer
			log.InitLogfmtForT(t, &logs)

			var fetched bool

			fetch.Subscribe(func(_ context.Context, _ core.Duty, set core.UnsignedDataSet) error {
				proposal, ok := set[pubkey].(core.VersionedProposal)
				require.True(t, ok)
				require.Equal(t, tt.wantURL, proposal.BuilderURL)

				// The fetched proposal can always be agreed.
				_, err := proposal.MarshalSSZ()
				require.NoError(t, err)

				fetched = true

				return nil
			})

			defSet := core.DutyDefinitionSet{pubkey: core.NewProposerDefinition(&eth2v1.ProposerDuty{Slot: slot, ValidatorIndex: 2})}
			require.NoError(t, fetch.Fetch(t.Context(), core.NewProposerDuty(slot), defSet))
			require.True(t, fetched)

			// The log line carries the same fields for every builder source.
			require.Contains(t, logs.String(), "Fetched gloas proposal")
			require.Contains(t, logs.String(), "builder_index=")
			require.Contains(t, logs.String(), "builder_url=")

			// Each fetched proposal's values are added in gwei, the bid only for builder bids and the
			// execution value only when known.
			requireObserved := func(typ string, want float64, observed bool) {
				t.Helper()

				after := valueOf(typ)
				if !observed {
					require.Equal(t, before[typ], after, typ)
					return
				}

				require.InDelta(t, before[typ].count+1, after.count, 0, typ)
				require.InDelta(t, before[typ].sum+want, after.sum, 0.001, typ)
			}

			requireObserved(proposalValueBid, bidValueGwei, !tt.selfBuilt)
			requireObserved(proposalValueExecution, 67_000_000.5, !tt.selfBuilt)
			requireObserved(proposalValueConsensus, 40_000_000, true)

			require.Equal(t, 1, promtest.CollectAndCount(proposalBlindedGauge))
			require.InDelta(t, tt.wantGauge, promtest.ToFloat64(proposalBlindedGauge.WithLabelValues(tt.wantLabel)), 0)
		})
	}
}
