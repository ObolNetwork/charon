// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/obolnetwork/charon/app/errors"
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

func eventHandler(event *sseclient.Event, url string) error {
	switch event.Event {
	case sseHead:
		var head SSEHead
		err := json.Unmarshal(event.Data, &head)
		if err != nil {
			return errors.Wrap(err, "unmarshal SSE head event", z.Str("url", url))
		}
		slot, err := strconv.ParseUint(head.Slot, 10, 64)
		if err != nil {
			return errors.Wrap(err, "parse slot to uint64", z.Str("url", url))
		}
		sseHeadGauge.WithLabelValues(url, head.Block, "TODO: add latency").Set(float64(slot))
	case sseChainReorg:
		var chainReorg SSEChainReorg
		err := json.Unmarshal(event.Data, &chainReorg)
		if err != nil {
			return errors.Wrap(err, "unmarshal SSE chain_reorg event", z.Str("url", url))
		}
		slot, err := strconv.ParseUint(chainReorg.Slot, 10, 64)
		if err != nil {
			return errors.Wrap(err, "parse slot to uint64", z.Str("url", url))
		}
		sseChainReorgGauge.WithLabelValues(url, chainReorg.Depth, chainReorg.OldHeadBlock, chainReorg.NewHeadBlock).Set(float64(slot))
	default:
	}

	return nil
}

func bnMetrics(ctx context.Context, conf Config) error {
	topics := queryTopics([]string{sseHead, sseChainReorg})
	headers, err := eth2util.ParseBeaconNodeHeaders(conf.BeaconNodeHeaders)
	if err != nil {
		return err
	}
	for _, bn := range conf.BeaconNodeAddrs {
		client := sseclient.New(bn + "/eth/v1/events" + topics)
		for k, v := range headers {
			client.Headers.Add(k, v)
		}
		go func() {
			err = client.Start(ctx, eventHandler, sseErrorHandler)
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
