// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package sse

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
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
	SubscribeChainReorgEvent(ChainReorgEventHandlerFunc)
}

type listener struct {
	sync.Mutex

	chainReorgSubs []ChainReorgEventHandlerFunc
	lastReorgEpoch eth2p0.Epoch

	// immutable fields
	genesisTime   time.Time
	slotDuration  time.Duration
	slotsPerEpoch uint64
}

var _ Listener = (*listener)(nil)

func StartListener(ctx context.Context, eth2Cl eth2wrap.Client, addresses, headers []string) (Listener, error) {
	// It is fine to use response from eth2cl (and respectively response from one of the nodes),
	// as configurations are per network and not per node.
	genesisTime, err := eth2wrap.FetchGenesisTime(ctx, eth2Cl)
	if err != nil {
		return nil, err
	}

	slotDuration, slotsPerEpoch, err := eth2wrap.FetchSlotsConfig(ctx, eth2Cl)
	if err != nil {
		return nil, err
	}

	l := &listener{
		chainReorgSubs: make([]ChainReorgEventHandlerFunc, 0),
		genesisTime:    genesisTime,
		slotDuration:   slotDuration,
		slotsPerEpoch:  slotsPerEpoch,
	}

	parsedHeaders, err := eth2util.ParseHTTPHeaders(headers)
	if err != nil {
		return nil, err
	}

	httpHeader := make(http.Header)
	for k, v := range parsedHeaders {
		httpHeader.Add(k, v)
	}

	// Open connections for each beacon node.
	for _, addr := range addresses {
		go func(addr string) {
			client, err := newClient(addr, httpHeader)
			if err != nil {
				log.Warn(ctx, "Failed to create SSE client", err, z.Str("addr", addr))
			} else {
				if err := client.start(ctx, l.eventHandler); err != nil {
					log.Warn(ctx, "Failed to start SSE client", err, z.Str("addr", addr))
				}
			}
		}(addr)
	}

	return l, nil
}

func (p *listener) SubscribeChainReorgEvent(handler ChainReorgEventHandlerFunc) {
	p.Lock()
	defer p.Unlock()

	p.chainReorgSubs = append(p.chainReorgSubs, handler)
}

func (p *listener) eventHandler(ctx context.Context, event *event, addr string) error {
	switch event.Event {
	case sseHeadEvent:
		return p.handleHeadEvent(ctx, event, addr)
	case sseChainReorgEvent:
		return p.handleChainReorgEvent(ctx, event, addr)
	case sseBlockGossipEvent:
		return p.handleBlockGossipEvent(ctx, event, addr)
	case sseBlockEvent:
		return p.handleBlockEvent(ctx, event, addr)
	default:
		return nil
	}
}

func (p *listener) handleHeadEvent(ctx context.Context, event *event, addr string) error {
	var head headEventData

	err := json.Unmarshal(event.Data, &head)
	if err != nil {
		return errors.Wrap(err, "unmarshal SSE head event", z.Str("addr", addr))
	}

	slot, err := strconv.ParseUint(head.Slot, 10, 64)
	if err != nil {
		return errors.Wrap(err, "parse slot to uint64", z.Str("addr", addr))
	}

	if slot > math.MaxInt64 {
		return errors.New("slot value exceeds int64 range", z.Str("addr", addr), z.U64("slot", slot))
	}

	delay, ok := p.computeDelay(slot, event.Timestamp, func(delay time.Duration) bool {
		// Chain's head is updated upon majority of the chain voting with attestations for a block.
		// Realistically this happens between 2/3 and 3/3 of the slot's timeframe.
		return delay < p.slotDuration
	})
	if !ok {
		log.Debug(ctx, "Beacon node received head event too late", z.U64("slot", slot), z.Str("delay", delay.String()))
	} else {
		sseHeadDelayHistogram.WithLabelValues(addr).Observe(delay.Seconds())
	}

	sseHeadSlotGauge.WithLabelValues(addr).Set(float64(slot))

	log.Debug(ctx, "SSE head event",
		z.U64("slot", slot),
		z.Str("delay", delay.String()),
		z.Str("block", head.Block),
		z.Str("prev_ddr", head.PreviousDutyDependentRoot),
		z.Str("curr_ddr", head.CurrentDutyDependentRoot))

	return nil
}

func (p *listener) handleChainReorgEvent(ctx context.Context, event *event, addr string) error {
	var chainReorg chainReorgEventData

	err := json.Unmarshal(event.Data, &chainReorg)
	if err != nil {
		return errors.Wrap(err, "unmarshal SSE chain_reorg event", z.Str("addr", addr))
	}

	slot, err := strconv.ParseUint(chainReorg.Slot, 10, 64)
	if err != nil {
		return errors.Wrap(err, "parse slot to uint64", z.Str("addr", addr))
	}

	depth, err := strconv.ParseUint(chainReorg.Depth, 10, 64)
	if err != nil {
		return errors.Wrap(err, "parse depth to uint64", z.Str("addr", addr))
	}

	if slot < depth {
		log.Warn(ctx, "Invalid chain reorg event: depth exceeds slot", nil, z.U64("slot", slot), z.U64("depth", depth))
		return errors.New("invalid chain reorg event: depth exceeds slot")
	}

	reorgEpoch := (slot - depth) / p.slotsPerEpoch
	p.notifyChainReorg(ctx, eth2p0.Epoch(reorgEpoch))

	log.Debug(ctx, "SSE chain reorg event",
		z.U64("slot", slot),
		z.Str("epoch", chainReorg.Epoch),
		z.U64("reorg_epoch", reorgEpoch),
		z.U64("depth", depth),
		z.Str("old_head_block", chainReorg.OldHeadBlock),
		z.Str("new_head_block", chainReorg.NewHeadBlock))

	sseChainReorgDepthHistogram.WithLabelValues(addr).Observe(float64(depth))

	return nil
}

func (p *listener) handleBlockGossipEvent(ctx context.Context, event *event, addr string) error {
	var blockGossip blockGossipEventData

	err := json.Unmarshal(event.Data, &blockGossip)
	if err != nil {
		return errors.Wrap(err, "unmarshal SSE block_gossip event", z.Str("addr", addr))
	}

	slot, err := strconv.ParseUint(blockGossip.Slot, 10, 64)
	if err != nil {
		return errors.Wrap(err, "parse slot to uint64", z.Str("addr", addr))
	}

	delay, ok := p.computeDelay(slot, event.Timestamp, func(delay time.Duration) bool {
		// Beacon node should receive a block via P2P or API between 0/3 and 1/3 of the slot's timeframe.
		return delay < (p.slotDuration / 3)
	})
	if !ok {
		log.Debug(ctx, "Beacon node received block_gossip event too late", z.U64("slot", slot), z.Str("delay", delay.String()))
	}

	log.Debug(ctx, "SSE block gossip event",
		z.U64("slot", slot),
		z.Str("delay", delay.String()),
		z.Str("block", blockGossip.Block))

	sseBlockGossipHistogram.WithLabelValues(addr).Observe(float64(delay))

	return nil
}

func (p *listener) handleBlockEvent(ctx context.Context, event *event, addr string) error {
	var block blockEventData

	err := json.Unmarshal(event.Data, &block)
	if err != nil {
		return errors.Wrap(err, "unmarshal SSE block event", z.Str("addr", addr))
	}

	slot, err := strconv.ParseUint(block.Slot, 10, 64)
	if err != nil {
		return errors.Wrap(err, "parse slot to uint64", z.Str("addr", addr))
	}

	delay, ok := p.computeDelay(slot, event.Timestamp, func(delay time.Duration) bool {
		// Beacon node should import a block to its fork-choice between 0/3 and 1/3 of the slot's timeframe.
		return delay < (p.slotDuration / 3)
	})
	if !ok {
		log.Debug(ctx, "Beacon node received block event too late", z.U64("slot", slot), z.Str("delay", delay.String()))
	}

	log.Debug(ctx, "SSE block event",
		z.U64("slot", slot),
		z.Str("delay", delay.String()),
		z.Str("block", block.Block))

	sseBlockHistogram.WithLabelValues(addr).Observe(float64(delay))

	return nil
}

func (p *listener) notifyChainReorg(ctx context.Context, epoch eth2p0.Epoch) {
	p.Lock()
	defer p.Unlock()

	if epoch == p.lastReorgEpoch {
		return
	}

	p.lastReorgEpoch = epoch
	for _, sub := range p.chainReorgSubs {
		sub(ctx, epoch)
	}
}

// Compute delay between start of the slot and receiving the event.
func (p *listener) computeDelay(slot uint64, eventTS time.Time, delayOKFunc func(delay time.Duration) bool) (time.Duration, bool) {
	slotStartTime := p.genesisTime.Add(time.Duration(slot) * p.slotDuration)
	delay := eventTS.Sub(slotStartTime)

	// calculate time of receiving the event - the time of start of the slot
	return delay, delayOKFunc(delay)
}
