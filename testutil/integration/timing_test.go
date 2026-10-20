// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package integration_test

import (
	"context"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

// TestSimnetDutyTimingGloasMigration asserts that intra-slot duty timings migrate from
// pre-gloas thirds to gloas quarters at the fork boundary, by observing the beacon node
// side of a full cluster with mock VCs performing all duties across the fork transition.
func TestSimnetDutyTimingGloasMigration(t *testing.T) {
	skipIfDisabled(t)

	// Whole seconds only, since it is published as SECONDS_PER_SLOT.
	const slotDuration = time.Second

	args := newSimnetArgs(t)
	args.VMocks = true

	// The simnet app derives the beaconmock genesis from the cluster fork version.
	genesis, err := eth2util.ForkVersionToGenesisTime(args.Lock.ForkVersion)
	require.NoError(t, err)

	// Simnet uses one slot per epoch, so epochs equal slots.
	startSlot := uint64(time.Since(genesis)/slotDuration) + 1
	// Startup margin so the slow pre-fork duties (sync contributions) are observed.
	forkSlot := startSlot + 12
	forkTime := genesis.Add(time.Duration(forkSlot) * slotDuration)

	t.Logf("genesis=%v startSlot=%d forkSlot=%d forkTime=%v", genesis, startSlot, forkSlot, forkTime)

	rec := newTimingRecorder(genesis, slotDuration, forkSlot)
	args.BMockOpts = append(args.BMockOpts,
		beaconmock.WithSlotDuration(slotDuration),
		beaconmock.WithSpecOverride("GLOAS_FORK_VERSION", "0x07000000"),
		beaconmock.WithSpecOverride("GLOAS_FORK_EPOCH", strconv.FormatUint(forkSlot, 10)),
		// Make every validator an aggregator so aggregations happen every slot.
		beaconmock.WithSpecOverride("TARGET_AGGREGATORS_PER_COMMITTEE", "1000000"),
		beaconmock.WithSpecOverride("TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE", "1000000"),
		beaconmock.WithNoProposerDuties(),
		beaconmock.WithDeterministicSyncCommDuties(2, 2),
		beaconmock.WithDeterministicPTCDuties(2, 2),
		rec.option(),
	)

	expect := newSimnetExpect(args.N,
		core.DutyPrepareAggregator, core.DutyAttester, core.DutyAggregator,
		core.DutyPrepareSyncContribution, core.DutySyncMessage, core.DutySyncContribution,
		core.DutyPayloadAttestation, // Only completes once gloas activates, keeping the test alive across the fork.
	)
	testSimnet(t, args, expect)

	require.Greater(t, time.Now(), forkTime, "test finished before the gloas fork activated")

	// Assertion windows use spec basis points and the millisecond rounding of core.NewSlotOffsetFunc.
	bps := func(bps int64) time.Duration {
		return time.Duration(int64(slotDuration) * bps / 10000).Round(time.Millisecond)
	}

	// Pre-gloas duties are due at thirds of the slot.
	rec.assertMinOffset(t, "attestation_data", false, bps(3333), bps(6667))
	rec.assertMinOffset(t, "aggregate_attestation", false, bps(6667), slotDuration)
	rec.assertMinOffset(t, "sync_message", false, bps(3333), bps(6667))
	rec.assertMinOffset(t, "sync_contribution", false, bps(6667), slotDuration)
	rec.assertNone(t, "payload_attestation_data", false)

	// Gloas duties are due at quarters of the slot.
	rec.assertMinOffset(t, "attestation_data", true, bps(2500), bps(3333))
	rec.assertMinOffset(t, "aggregate_attestation", true, bps(5000), bps(6667))
	rec.assertMinOffset(t, "sync_message", true, bps(2500), bps(3333))
	rec.assertMinOffset(t, "sync_contribution", true, bps(5000), bps(6667))
	rec.assertMinOffset(t, "payload_attestation_data", true, bps(5000), bps(7500))
}

// timingRecorder records the intra-slot offsets at which beaconmock endpoints are hit.
type timingRecorder struct {
	genesis      time.Time
	slotDuration time.Duration
	forkSlot     uint64

	mu      sync.Mutex
	offsets map[string][]time.Duration // Keyed by "<metric>|pre" or "<metric>|post".
}

func newTimingRecorder(genesis time.Time, slotDuration time.Duration, forkSlot uint64) *timingRecorder {
	return &timingRecorder{
		genesis:      genesis,
		slotDuration: slotDuration,
		forkSlot:     forkSlot,
		offsets:      make(map[string][]time.Duration),
	}
}

func (r *timingRecorder) record(metric string, slot eth2p0.Slot) {
	offset := time.Since(r.genesis.Add(time.Duration(slot) * r.slotDuration))

	key := metric + "|pre"
	if uint64(slot) >= r.forkSlot {
		key = metric + "|post"
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.offsets[key] = append(r.offsets[key], offset)
}

func (r *timingRecorder) get(metric string, postFork bool) []time.Duration {
	key := metric + "|pre"
	if postFork {
		key = metric + "|post"
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	return slices.Clone(r.offsets[key])
}

// assertMinOffset asserts that the earliest observed offset of the metric is within
// [minOffset, maxOffset), since delays only ever push observations later.
func (r *timingRecorder) assertMinOffset(t *testing.T, metric string, postFork bool, minOffset, maxOffset time.Duration) {
	t.Helper()

	offsets := r.get(metric, postFork)
	require.NotEmptyf(t, offsets, "no %v observations (post_fork=%v)", metric, postFork)

	earliest := slices.Min(offsets)
	require.GreaterOrEqualf(t, earliest, minOffset, "%v triggered before its due offset (post_fork=%v)", metric, postFork)
	require.Lessf(t, earliest, maxOffset, "%v triggered too late for its due offset (post_fork=%v)", metric, postFork)
}

func (r *timingRecorder) assertNone(t *testing.T, metric string, postFork bool) {
	t.Helper()
	require.Emptyf(t, r.get(metric, postFork), "unexpected %v observations (post_fork=%v)", metric, postFork)
}

// option returns a beaconmock option wrapping the duty related endpoints with timing recording.
func (r *timingRecorder) option() beaconmock.Option {
	return func(mock *beaconmock.Mock) {
		attInner := mock.AttestationDataFunc
		mock.AttestationDataFunc = func(ctx context.Context, slot eth2p0.Slot, commIdx eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error) {
			r.record("attestation_data", slot)
			return attInner(ctx, slot, commIdx)
		}

		aggInner := mock.AggregateAttestationFunc
		mock.AggregateAttestationFunc = func(ctx context.Context, slot eth2p0.Slot, root eth2p0.Root) (*eth2spec.VersionedAttestation, error) {
			r.record("aggregate_attestation", slot)
			return aggInner(ctx, slot, root)
		}

		syncMsgInner := mock.SubmitSyncCommitteeMessagesFunc
		mock.SubmitSyncCommitteeMessagesFunc = func(ctx context.Context, messages []*altair.SyncCommitteeMessage) error {
			for _, msg := range messages {
				r.record("sync_message", msg.Slot)
			}

			return syncMsgInner(ctx, messages)
		}

		contribInner := mock.SyncCommitteeContributionFunc
		mock.SyncCommitteeContributionFunc = func(ctx context.Context, slot eth2p0.Slot, subcommIdx uint64, root eth2p0.Root) (*altair.SyncCommitteeContribution, error) {
			r.record("sync_contribution", slot)
			return contribInner(ctx, slot, subcommIdx, root)
		}

		padInner := mock.PayloadAttestationDataFunc
		mock.PayloadAttestationDataFunc = func(ctx context.Context, slot eth2p0.Slot) (*eth2spec.VersionedPayloadAttestationData, error) {
			r.record("payload_attestation_data", slot)
			return padInner(ctx, slot)
		}
	}
}
