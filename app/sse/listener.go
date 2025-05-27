// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package sse

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
)

type ChainReorgEventHandlerFunc func(ctx context.Context, epoch eth2p0.Epoch)

type Listener interface {
	Start(ctx context.Context) error
	SubscribeChainReorgEvent(ChainReorgEventHandlerFunc)
}

type listener struct {
	sync.RWMutex

	eth2Cl         eth2wrap.Client
	addresses      []string
	headers        []string
	chainReorgSubs []ChainReorgEventHandlerFunc
	genesisTime    time.Time
	slotDuration   time.Duration
	slotsPerEpoch  uint64
}

var _ Listener = (*listener)(nil)

func NewListener(eth2Cl eth2wrap.Client, addresses, headers []string) Listener {
	return &listener{
		chainReorgSubs: make([]ChainReorgEventHandlerFunc, 0),
		eth2Cl:         eth2Cl,
		addresses:      addresses,
		headers:        headers,
	}
}

func (p *listener) SubscribeChainReorgEvent(handler ChainReorgEventHandlerFunc) {
	p.Lock()
	defer p.Unlock()

	p.chainReorgSubs = append(p.chainReorgSubs, handler)
}

func (p *listener) Start(ctx context.Context) error {
	// It is fine to use response from eth2cl (and respectively response from one of the nodes),
	// as configurations are per network and not per node.
	genesisTime, err := eth2wrap.FetchGenesisTime(ctx, p.eth2Cl)
	if err != nil {
		return err
	}
	slotDuration, slotsPerEpoch, err := eth2wrap.FetchSlotsConfig(ctx, p.eth2Cl)
	if err != nil {
		return err
	}

	// We set this once, but in case of a hardfork these won't update.
	p.Lock()
	p.genesisTime = genesisTime
	p.slotDuration = slotDuration
	p.slotsPerEpoch = slotsPerEpoch
	p.Unlock()

	topics := queryTopics([]string{sseHeadEvent, sseChainReorgEvent})
	parsedHeaders, err := eth2util.ParseBeaconNodeHeaders(p.headers)
	if err != nil {
		return err
	}
	httpHeader := make(http.Header)
	for k, v := range parsedHeaders {
		httpHeader.Add(k, v)
	}

	// Open connections for each beacon node.
	for _, addr := range p.addresses {
		go func(addr string) {
			client := newClient(addr+"/eth/v1/events"+topics, httpHeader)
			if err := client.Start(ctx, p.eventHandler); err != nil {
				log.Warn(ctx, "Failed to start SSE client", err, z.Str("address", addr))
			}
		}(addr)
	}

	return nil
}

func (p *listener) eventHandler(ctx context.Context, event *event, url string) error {
	switch event.Event {
	case sseHeadEvent:
		return p.handleHeadEvent(ctx, event, url)
	case sseChainReorgEvent:
		return p.handleChainReorgEvent(ctx, event, url)
	default:
		return nil
	}
}

func (p *listener) handleHeadEvent(ctx context.Context, event *event, url string) error {
	var head headEventData
	err := json.Unmarshal(event.Data, &head)
	if err != nil {
		return errors.Wrap(err, "unmarshal SSE head event", z.Str("url", url))
	}
	slot, err := strconv.ParseUint(head.Slot, 10, 64)
	if err != nil {
		return errors.Wrap(err, "parse slot to uint64", z.Str("url", url))
	}
	if slot > math.MaxInt64 {
		return errors.New("slot value exceeds int64 range", z.Str("url", url), z.U64("slot", slot))
	}
	delay, ok := p.computeDelay(slot, event.Timestamp)
	if !ok {
		log.Debug(ctx, "Beacon node received head event too late", z.U64("slot", slot), z.Str("delay", delay.String()))
	} else {
		sseHeadDelayHistogram.WithLabelValues(url).Observe(float64(delay.Milliseconds()))
	}

	sseHeadSlotGauge.WithLabelValues(url).Set(float64(slot))

	return nil
}

func (p *listener) handleChainReorgEvent(ctx context.Context, event *event, url string) error {
	var chainReorg chainReorgData
	err := json.Unmarshal(event.Data, &chainReorg)
	if err != nil {
		return errors.Wrap(err, "unmarshal SSE chain_reorg event", z.Str("url", url))
	}
	slot, err := strconv.ParseUint(chainReorg.Slot, 10, 64)
	if err != nil {
		return errors.Wrap(err, "parse slot to uint64", z.Str("url", url))
	}
	if slot > math.MaxInt64 {
		return errors.New("slot value exceeds int64 range", z.Str("url", url), z.U64("slot", slot))
	}
	depth, err := strconv.ParseUint(chainReorg.Depth, 10, 64)
	if err != nil {
		return errors.Wrap(err, "parse depth to uint64", z.Str("url", url))
	}
	if slot < depth {
		log.Warn(ctx, "Invalid chain reorg event: depth exceeds slot", nil, z.U64("slot", slot), z.U64("depth", depth))
		return errors.New("invalid chain reorg event: depth exceeds slot")
	}

	reorgEpoch := (slot - depth) / p.slotsPerEpoch
	p.notifyChainReorg(ctx, eth2p0.Epoch(reorgEpoch))

	log.Debug(ctx, "Beacon node reorged", z.U64("slot", slot), z.U64("depth", depth))

	sseChainReorgDepthGauge.WithLabelValues(url).Set(float64(depth))

	return nil
}

func (p *listener) notifyChainReorg(ctx context.Context, epoch eth2p0.Epoch) {
	p.RLock()
	defer p.RUnlock()

	for _, sub := range p.chainReorgSubs {
		sub(ctx, epoch)
	}
}

// Compute delay between start of the slot and receiving the head update event.
func (p *listener) computeDelay(slot uint64, eventTS time.Time) (time.Duration, bool) {
	slotStartTime := p.genesisTime.Add(time.Duration(slot) * p.slotDuration)
	delay := eventTS.Sub(slotStartTime)
	// Chain's head is updated upon majority of the chain voting with attestations for a block.
	// Realistically this happens between 2/3 and 3/3 of the slot's timeframe.
	delayOK := delay < p.slotDuration

	// calculate time of receiving the event - the time of start of the slot
	return delay, delayOK
}

func queryTopics(topics []string) string {
	var builder strings.Builder
	builder.WriteString("?")
	for i, t := range topics {
		if i > 0 {
			builder.WriteString("&")
		}
		builder.WriteString("topics=")
		builder.WriteString(t)
	}
	return builder.String()
}
