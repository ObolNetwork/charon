// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/sseclient"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
)

const (
	sseHead       = "head"
	sseChainReorg = "chain_reorg"
)

type SSEHead struct {
	Slot                      string `json:"slot"`
	Block                     string `json:"block"`
	State                     string `json:"state"`
	EpochTransition           bool   `json:"epoch_transition"`
	PreviousDutyDependentRoot string `json:"previous_duty_dependent_root"`
	CurrentDutyDependentRoot  string `json:"current_duty_dependent_root"`
	ExecutionOptimistic       bool   `json:"execution_optimistic"`
}

type SSEChainReorg struct {
	Slot                string `json:"slot"`
	Depth               string `json:"depth"`
	OldHeadBlock        string `json:"old_head_block"`
	NewHeadBlock        string `json:"new_head_block"`
	OldHeadState        string `json:"old_head_state"`
	NewHeadState        string `json:"new_head_state"`
	Epoch               string `json:"epoch"`
	ExecutionOptimistic string `json:"execution_optimistic"`
}

func sseErrorHandler(err error, url string) error {
	return errors.Wrap(err, "handle SSE payload", z.Str("url", url))
}

func sseEventHandler(ctx context.Context, event *sseclient.Event, url string, opts map[string]string) error {
	switch event.Event {
	case sseHead:
		var head SSEHead
		err := json.Unmarshal(event.Data, &head)
		if err != nil {
			return errors.Wrap(err, "unmarshal SSE head event", z.Str("url", url))
		}
		slot, err := strconv.ParseInt(head.Slot, 10, 64)
		if err != nil {
			return errors.Wrap(err, "parse slot to uint64", z.Str("url", url))
		}
		delay, err := computeDelay(slot, event.Timestamp, opts)
		if err != nil {
			return errors.Wrap(err, "compute delay", z.Str("url", url))
		}
		if delay > 4*time.Second {
			log.Debug(ctx, "Beacon node received head event too late", z.I64("slot", slot), z.Str("delay", delay.String()))
		}
		sseHeadGauge.WithLabelValues(url, head.Block, delay.String()).Set(float64(slot))
	case sseChainReorg:
		var chainReorg SSEChainReorg
		err := json.Unmarshal(event.Data, &chainReorg)
		if err != nil {
			return errors.Wrap(err, "unmarshal SSE chain_reorg event", z.Str("url", url))
		}
		slot, err := strconv.ParseInt(chainReorg.Slot, 10, 64)
		if err != nil {
			return errors.Wrap(err, "parse slot to uint64", z.Str("url", url))
		}
		log.Debug(ctx, "Beacon node reorged", z.I64("slot", slot), z.Str("depth", chainReorg.Depth))
		sseChainReorgGauge.WithLabelValues(url, chainReorg.Depth, chainReorg.OldHeadBlock, chainReorg.NewHeadBlock).Set(float64(slot))
	default:
	}

	return nil
}

// Compute delay between start of the slot and receiving the head update event.
func computeDelay(slot int64, eventTS time.Time, opts map[string]string) (time.Duration, error) {
	slotDurationOpt, ok := opts["slotDuration"]
	if !ok {
		return 0, errors.New("fetch slotDuration from options")
	}
	genesisTimeOpt, ok := opts["genesisTime"]
	if !ok {
		return 0, errors.New("fetch genesisTime from options")
	}

	slotDuration, err := time.ParseDuration(slotDurationOpt)
	if err != nil {
		return 0, errors.Wrap(err, "parse slotDuration to time.Duration")
	}
	genesisTime, err := time.Parse(time.RFC3339, genesisTimeOpt)
	if err != nil {
		return 0, errors.Wrap(err, "parse genesisTime to RFC3339 time.Time")
	}

	slotStartTime := genesisTime.Add(time.Second * time.Duration((slot-1)*int64(slotDuration.Seconds())))

	// calculate time of receiving the event - the time of start of the slot
	return eventTS.Sub(slotStartTime), nil
}

// Start long running connection on endpoint /eth/v1/events with all configured beacon nodes.
// Gather metrics and send them to prometheus.
func bnMetrics(ctx context.Context, conf Config, eth2Cl eth2wrap.Client) error {
	// It is fine to use response from eth2cl (and respectively response from one of the nodes),
	// as configurations are per network and not per node.
	eth2Spec, err := eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
	if err != nil {
		return err
	}
	slotDuration, ok := eth2Spec.Data["SECONDS_PER_SLOT"].(time.Duration)
	if !ok {
		return errors.New("fetch slot duration")
	}

	eth2Genesis, err := eth2Cl.Genesis(ctx, &eth2api.GenesisOpts{})
	if err != nil {
		return err
	}
	genesisTime := eth2Genesis.Data.GenesisTime

	opts := map[string]string{
		"slotDuration": slotDuration.String(),
		"genesisTime":  genesisTime.Format(time.RFC3339),
	}

	topics := queryTopics([]string{sseHead, sseChainReorg})
	headers, err := eth2util.ParseBeaconNodeHeaders(conf.BeaconNodeHeaders)
	if err != nil {
		return err
	}
	// Open connections for each beacon node.
	for _, bn := range conf.BeaconNodeAddrs {
		client := sseclient.New(bn + "/eth/v1/events" + topics)
		for k, v := range headers {
			client.Headers.Add(k, v)
		}
		go func() {
			err = client.Start(ctx, sseEventHandler, sseErrorHandler, opts)
			if err != nil {
				log.Warn(ctx, "Failed to start SSE client", err)
			}
		}()
	}

	return nil
}

func queryTopics(topics []string) string {
	query := "?"
	for _, t := range topics {
		query += "topics=" + t + "&"
	}

	return query
}
