// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package sse

import (
	"context"
	"testing"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestHandleEvents(t *testing.T) {
	tests := []struct {
		name  string
		event *event
		err   error
	}{
		{
			name: "head happy path",
			event: &event{
				Event:     sseHeadEvent,
				Data:      []byte(`{"slot":"10", "block":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "state":"0x600e852a08c1200654ddf11025f1ceacb3c2e74bdd5c630cde0838b2591b69f9", "epoch_transition":false, "previous_duty_dependent_root":"0x5e0043f107cb57913498fbf2f99ff55e730bf1e151f02f221e977c91a90a0e91", "current_duty_dependent_root":"0x5e0043f107cb57913498fbf2f99ff55e730bf1e151f02f221e977c91a90a0e91", "execution_optimistic": false}`),
				Timestamp: time.Now(),
			},
			err: nil,
		},
		{
			name: "head incompatible data payload",
			event: &event{
				Event:     sseHeadEvent,
				Data:      []byte(`"error"`),
				Timestamp: time.Now(),
			},
			err: errors.New("unmarshal SSE head event"),
		},
		{
			name: "head parse slot",
			event: &event{
				Event:     sseHeadEvent,
				Data:      []byte(`{"slot":"ten", "block":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "state":"0x600e852a08c1200654ddf11025f1ceacb3c2e74bdd5c630cde0838b2591b69f9", "epoch_transition":false, "previous_duty_dependent_root":"0x5e0043f107cb57913498fbf2f99ff55e730bf1e151f02f221e977c91a90a0e91", "current_duty_dependent_root":"0x5e0043f107cb57913498fbf2f99ff55e730bf1e151f02f221e977c91a90a0e91", "execution_optimistic": false}`),
				Timestamp: time.Now(),
			},
			err: errors.New("parse slot to uint64"),
		},
		{
			name: "chain_reorg happy path",
			event: &event{
				Event:     sseChainReorgEvent,
				Data:      []byte(`{"slot":"200", "depth":"50", "old_head_block":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "new_head_block":"0x76262e91970d375a19bfe8a867288d7b9cde43c8635f598d93d39d041706fc76", "old_head_state":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "new_head_state":"0x600e852a08c1200654ddf11025f1ceacb3c2e74bdd5c630cde0838b2591b69f9", "epoch":"2", "execution_optimistic": false}`),
				Timestamp: time.Now(),
			},
			err: nil,
		},
		{
			name: "chain_reorg incompatible data payload",
			event: &event{
				Event:     sseChainReorgEvent,
				Data:      []byte(`"error"`),
				Timestamp: time.Now(),
			},
			err: errors.New("unmarshal SSE chain_reorg event"),
		},
		{
			name: "chain_reorg parse slot",
			event: &event{
				Event:     sseChainReorgEvent,
				Data:      []byte(`{"slot":"ten", "depth":"50", "old_head_block":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "new_head_block":"0x76262e91970d375a19bfe8a867288d7b9cde43c8635f598d93d39d041706fc76", "old_head_state":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "new_head_state":"0x600e852a08c1200654ddf11025f1ceacb3c2e74bdd5c630cde0838b2591b69f9", "epoch":"2", "execution_optimistic": false}`),
				Timestamp: time.Now(),
			},
			err: errors.New("parse slot to uint64"),
		},
		{
			name: "chain_reorg parse depth",
			event: &event{
				Event:     sseChainReorgEvent,
				Data:      []byte(`{"slot":"1", "depth":"x50", "old_head_block":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "new_head_block":"0x76262e91970d375a19bfe8a867288d7b9cde43c8635f598d93d39d041706fc76", "old_head_state":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "new_head_state":"0x600e852a08c1200654ddf11025f1ceacb3c2e74bdd5c630cde0838b2591b69f9", "epoch":"2", "execution_optimistic": false}`),
				Timestamp: time.Now(),
			},
			err: errors.New("parse depth to uint64"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			l := &listener{
				chainReorgSubs: make([]ChainReorgEventHandlerFunc, 0),
				slotDuration:   12 * time.Second,
				slotsPerEpoch:  32,
				genesisTime:    time.Date(2020, 12, 1, 12, 0, 23, 0, time.UTC),
			}

			err := l.eventHandler(t.Context(), test.event, "test")
			if test.err != nil {
				require.ErrorContains(t, err, test.err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestStartListener(t *testing.T) {
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	_, err = StartListener(t.Context(), bmock, []string{bmock.Address()}, []string{})
	require.NoError(t, err)
}

func TestSubscribeNotifyChainReorg(t *testing.T) {
	ctx := t.Context()
	l := &listener{
		chainReorgSubs: make([]ChainReorgEventHandlerFunc, 0),
	}

	reportedEpochs := make([]eth2p0.Epoch, 0)

	l.SubscribeChainReorgEvent(func(_ context.Context, epoch eth2p0.Epoch) {
		reportedEpochs = append(reportedEpochs, epoch)
	})

	l.notifyChainReorg(ctx, eth2p0.Epoch(5))
	l.notifyChainReorg(ctx, eth2p0.Epoch(5)) // Duplicate should not be reported again
	l.notifyChainReorg(ctx, eth2p0.Epoch(10))

	require.Len(t, reportedEpochs, 2)
	require.Equal(t, eth2p0.Epoch(5), reportedEpochs[0])
	require.Equal(t, eth2p0.Epoch(10), reportedEpochs[1])
}

func TestComputeDelay(t *testing.T) {
	genesisTimeString := "2020-12-01T12:00:23+00:00"
	genesisTime, err := time.Parse(time.RFC3339, genesisTimeString)
	require.NoError(t, err)

	slotDuration := 12 * time.Second

	tests := []struct {
		name       string
		slot       uint64
		eventTS    time.Time
		expected   time.Duration
		expectedOk bool
	}{
		{
			name:       "happy path",
			slot:       1,
			eventTS:    genesisTime.Add(slotDuration + 2*slotDuration/3), // 2/3 into slot 1
			expected:   2*slotDuration/3 + slotDuration,
			expectedOk: true,
		},
		{
			name:       "happy path, not ok",
			slot:       1,
			eventTS:    genesisTime.Add(2*slotDuration + time.Second), // 1 second into slot 2
			expected:   2*slotDuration + time.Second,
			expectedOk: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			l := &listener{
				genesisTime:   genesisTime,
				slotDuration:  slotDuration,
				slotsPerEpoch: 32,
			}

			res, ok := l.computeDelay(test.slot, test.eventTS)
			require.Equal(t, test.expected, res)
			require.Equal(t, test.expectedOk, ok)
		})
	}
}
