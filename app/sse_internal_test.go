// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/sseclient"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestSseEventHandler(t *testing.T) {
	tests := []struct {
		name  string
		event *sseclient.Event
		opts  map[string]string
		err   error
	}{
		{
			name: "head happy path",
			event: &sseclient.Event{
				Event:     sseHeadEvent,
				Data:      []byte(`{"slot":"10", "block":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "state":"0x600e852a08c1200654ddf11025f1ceacb3c2e74bdd5c630cde0838b2591b69f9", "epoch_transition":false, "previous_duty_dependent_root":"0x5e0043f107cb57913498fbf2f99ff55e730bf1e151f02f221e977c91a90a0e91", "current_duty_dependent_root":"0x5e0043f107cb57913498fbf2f99ff55e730bf1e151f02f221e977c91a90a0e91", "execution_optimistic": false}`),
				Timestamp: time.Now(),
			},
			opts: map[string]string{
				"slotDuration": "12s",
				"genesisTime":  "2020-12-01T12:00:23+00:00",
			},
			err: nil,
		},
		{
			name: "head incompatible data payload",
			event: &sseclient.Event{
				Event:     sseHeadEvent,
				Data:      []byte(`"error"`),
				Timestamp: time.Now(),
			},
			opts: map[string]string{
				"slotDuration": "12s",
				"genesisTime":  "2020-12-01T12:00:23+00:00",
			},
			err: errors.New("unmarshal SSE head event"),
		},
		{
			name: "head parse slot",
			event: &sseclient.Event{
				Event:     sseHeadEvent,
				Data:      []byte(`{"slot":"ten", "block":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "state":"0x600e852a08c1200654ddf11025f1ceacb3c2e74bdd5c630cde0838b2591b69f9", "epoch_transition":false, "previous_duty_dependent_root":"0x5e0043f107cb57913498fbf2f99ff55e730bf1e151f02f221e977c91a90a0e91", "current_duty_dependent_root":"0x5e0043f107cb57913498fbf2f99ff55e730bf1e151f02f221e977c91a90a0e91", "execution_optimistic": false}`),
				Timestamp: time.Now(),
			},
			opts: map[string]string{
				"slotDuration": "12s",
				"genesisTime":  "2020-12-01T12:00:23+00:00",
			},
			err: errors.New("parse slot to int64"),
		},
		{
			name: "head fetch missing opts",
			event: &sseclient.Event{
				Event:     sseHeadEvent,
				Data:      []byte(`{"slot":"10", "block":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "state":"0x600e852a08c1200654ddf11025f1ceacb3c2e74bdd5c630cde0838b2591b69f9", "epoch_transition":false, "previous_duty_dependent_root":"0x5e0043f107cb57913498fbf2f99ff55e730bf1e151f02f221e977c91a90a0e91", "current_duty_dependent_root":"0x5e0043f107cb57913498fbf2f99ff55e730bf1e151f02f221e977c91a90a0e91", "execution_optimistic": false}`),
				Timestamp: time.Now(),
			},
			opts: nil,
			err:  errors.New("compute delay"),
		},
		{
			name: "chain_reorg happy path",
			event: &sseclient.Event{
				Event:     sseChainReorgEvent,
				Data:      []byte(`{"slot":"200", "depth":"50", "old_head_block":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "new_head_block":"0x76262e91970d375a19bfe8a867288d7b9cde43c8635f598d93d39d041706fc76", "old_head_state":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "new_head_state":"0x600e852a08c1200654ddf11025f1ceacb3c2e74bdd5c630cde0838b2591b69f9", "epoch":"2", "execution_optimistic": false}`),
				Timestamp: time.Now(),
			},
			err: nil,
		},
		{
			name: "chain_reorg incompatible data payload",
			event: &sseclient.Event{
				Event:     sseChainReorgEvent,
				Data:      []byte(`"error"`),
				Timestamp: time.Now(),
			},
			err: errors.New("unmarshal SSE chain_reorg event"),
		},
		{
			name: "chain_reorg parse slot",
			event: &sseclient.Event{
				Event:     sseChainReorgEvent,
				Data:      []byte(`{"slot":"ten", "depth":"50", "old_head_block":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "new_head_block":"0x76262e91970d375a19bfe8a867288d7b9cde43c8635f598d93d39d041706fc76", "old_head_state":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "new_head_state":"0x600e852a08c1200654ddf11025f1ceacb3c2e74bdd5c630cde0838b2591b69f9", "epoch":"2", "execution_optimistic": false}`),
				Timestamp: time.Now(),
			},
			err: errors.New("parse slot to int64"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := sseEventHandler(t.Context(), test.event, "/url", test.opts)

			if test.err != nil {
				require.ErrorContains(t, err, test.err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSseErrorHandler(t *testing.T) {
	err := errors.New("sseErr")
	resErr := sseErrorHandler(err, "/events")
	require.ErrorContains(t, resErr, "handle SSE payload")
	require.ErrorContains(t, resErr, "sseErr")
}

func TestBnMetrics(t *testing.T) {
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	bmock.GenesisFunc = func(context.Context, *eth2api.GenesisOpts) (*eth2v1.Genesis, error) {
		return &eth2v1.Genesis{
			GenesisTime:           time.Unix(int64(1606824023), 0),
			GenesisValidatorsRoot: eth2p0.Root([]byte("0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")),
			GenesisForkVersion:    eth2p0.Version{0x00, 0x00, 0x00, 0x00},
		}, nil
	}

	bmock.EventsFunc = func(context.Context, *eth2api.EventsOpts) error {
		return nil
	}

	config := Config{
		BeaconNodeAddrs:   []string{bmock.Address()},
		BeaconNodeHeaders: []string{},
	}

	err = bnMetrics(t.Context(), config, bmock)
	require.NoError(t, err)
}

func TestComputeDelay(t *testing.T) {
	genesisTimeString := "2020-12-01T12:00:23+00:00"
	genesisTime, err := time.Parse(time.RFC3339, genesisTimeString)
	require.NoError(t, err)
	slotDurationString := "12s"
	slotDuration, err := time.ParseDuration(slotDurationString)
	require.NoError(t, err)

	tests := []struct {
		name       string
		slot       int64
		eventTS    time.Time
		opts       map[string]string
		expected   time.Duration
		expectedOk bool
		err        error
	}{
		{
			name:    "happy path",
			slot:    1,
			eventTS: genesisTime.Add(slotDuration + 2*3/slotDuration), // 2/3 into slot 1
			opts: map[string]string{
				"slotDuration": slotDurationString,
				"genesisTime":  genesisTimeString,
			},
			expected:   2 * 3 / slotDuration,
			expectedOk: true,
			err:        nil,
		},
		{
			name:    "happy path, not ok",
			slot:    1,
			eventTS: genesisTime.Add(2*slotDuration + time.Second), // 1 second into slot 2
			opts: map[string]string{
				"slotDuration": slotDurationString,
				"genesisTime":  genesisTimeString,
			},
			expected:   slotDuration + time.Second,
			expectedOk: false,
			err:        nil,
		},
		{
			name:    "slotDuration missing",
			slot:    1,
			eventTS: genesisTime.Add(slotDuration + 2*3/slotDuration),
			opts: map[string]string{
				"genesisTime": genesisTimeString,
			},
			err: errors.New("fetch slotDuration from options"),
		},
		{
			name:    "genesisTime missing",
			slot:    1,
			eventTS: genesisTime.Add(slotDuration + 2*3/slotDuration),
			opts: map[string]string{
				"slotDuration": slotDurationString,
			},
			err: errors.New("fetch genesisTime from options"),
		},
		{
			name:    "slotDuration unable to parse",
			slot:    1,
			eventTS: genesisTime.Add(slotDuration + 2*3/slotDuration),
			opts: map[string]string{
				"slotDuration": "error",
				"genesisTime":  genesisTimeString,
			},
			err: errors.New("parse slotDuration to time.Duration"),
		},
		{
			name:    "genesisTime unable to parse",
			slot:    1,
			eventTS: genesisTime.Add(slotDuration + 2*3/slotDuration),
			opts: map[string]string{
				"slotDuration": slotDurationString,
				"genesisTime":  "error",
			},
			err: errors.New("parse genesisTime to RFC3339 time.Time"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, ok, err := computeDelay(test.slot, test.eventTS, test.opts)

			if test.err != nil {
				require.ErrorContains(t, err, test.err.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, test.expected, res)
				require.Equal(t, test.expectedOk, ok)
			}
		})
	}
}
