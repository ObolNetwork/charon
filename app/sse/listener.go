// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package sse

import (
	"context"
	"encoding/hex"
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
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
)

type (
	ChainReorgEventHandlerFunc func(ctx context.Context, epoch eth2p0.Epoch)
	HeadEventHandlerFunc       func(ctx context.Context, slot eth2p0.Slot, blockRoot eth2p0.Root, bnAddr string)
	// DutiesDependentRootFunc returns the dependent root recorded with the epoch's cached attester duties, or false if unknown.
	DutiesDependentRootFunc func(epoch eth2p0.Epoch) (eth2p0.Root, bool)
)

type Listener interface {
	SubscribeChainReorgEvent(ChainReorgEventHandlerFunc)
	SubscribeHeadEvent(HeadEventHandlerFunc)
	// SetDutiesDependentRootFunc enables invalidating cached duties whose dependent root differs from head events.
	SetDutiesDependentRootFunc(DutiesDependentRootFunc)
}

type listener struct {
	sync.Mutex

	chainReorgSubs          []ChainReorgEventHandlerFunc
	headSubs                []HeadEventHandlerFunc
	dutiesDependentRootFunc DutiesDependentRootFunc
	lastReorgEpoch          eth2p0.Epoch

	// blockGossipTimes stores timestamps of block gossip events per slot and beacon node address
	// first key: slot, second key: beacon node address
	blockGossipTimes map[uint64]map[string]time.Time

	// immutable fields
	labels         map[string]string // Redacted beacon node addresses, used in logs and metric labels.
	genesisTime    time.Time
	slotDuration   time.Duration
	slotsPerEpoch  uint64
	slotOffsetFunc core.SlotOffsetFunc
}

var _ Listener = (*listener)(nil)

func StartListener(ctx context.Context, eth2Cl eth2wrap.Client, forkSchedule func() eth2wrap.ForkForkSchedule, addresses, headers []string) (Listener, error) {
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

	slotOffsetFunc, err := core.NewSlotOffsetFunc(ctx, eth2Cl, forkSchedule)
	if err != nil {
		return nil, err
	}

	l := &listener{
		chainReorgSubs:   make([]ChainReorgEventHandlerFunc, 0),
		headSubs:         make([]HeadEventHandlerFunc, 0),
		blockGossipTimes: make(map[uint64]map[string]time.Time),
		labels:           make(map[string]string),
		genesisTime:      genesisTime,
		slotDuration:     slotDuration,
		slotsPerEpoch:    slotsPerEpoch,
		slotOffsetFunc:   slotOffsetFunc,
	}

	parsedHeaders, err := eth2util.ParseHTTPHeaders(headers)
	if err != nil {
		return nil, err
	}

	httpHeader := make(http.Header)
	for k, v := range parsedHeaders {
		httpHeader.Add(k, v)
	}

	for _, addr := range addresses {
		l.labels[addr] = log.RedactURL(addr, true)
	}

	// Open connections for each beacon node.
	for _, addr := range addresses {
		go func(addr string) {
			client, err := newClient(addr, httpHeader)
			if err != nil {
				log.Warn(ctx, "Failed to create SSE client", err, z.Str("addr", l.label(addr)))
			} else {
				if err := client.start(ctx, l.eventHandler); err != nil {
					log.Warn(ctx, "Failed to start SSE client", err, z.Str("addr", l.label(addr)))
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

func (p *listener) SubscribeHeadEvent(handler HeadEventHandlerFunc) {
	p.Lock()
	defer p.Unlock()

	p.headSubs = append(p.headSubs, handler)
}

func (p *listener) SetDutiesDependentRootFunc(fn DutiesDependentRootFunc) {
	p.Lock()
	defer p.Unlock()

	p.dutiesDependentRootFunc = fn
}

// label returns the beacon node address without credentials, for logs and metric labels.
func (p *listener) label(addr string) string {
	if label, ok := p.labels[addr]; ok {
		return label
	}

	return log.RedactURL(addr, true)
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
		return errors.Wrap(err, "unmarshal SSE head event", z.Str("addr", p.label(addr)))
	}

	slot, err := strconv.ParseUint(head.Slot, 10, 64)
	if err != nil {
		return errors.Wrap(err, "parse slot to uint64", z.Str("addr", p.label(addr)))
	}

	if slot > math.MaxInt64 {
		return errors.New("slot value exceeds int64 range", z.Str("addr", p.label(addr)), z.U64("slot", slot))
	}

	delay, ok := p.computeDelay(slot, event.Timestamp, func(delay time.Duration) bool {
		// Chain's head is updated upon majority of the chain voting with attestations for a block.
		// Realistically this happens between 2/3 and 3/3 of the slot's timeframe.
		return delay < p.slotDuration
	})
	if !ok {
		log.Debug(ctx, "Beacon node received head event too late", z.U64("slot", slot), z.Str("delay", delay.String()))
	} else {
		sseHeadDelayHistogram.WithLabelValues(p.label(addr)).Observe(delay.Seconds())
	}

	sseHeadSlotGauge.WithLabelValues(p.label(addr)).Set(float64(slot))

	// Calculate and record block processing time
	p.recordBlockProcessingTime(slot, addr, event.Timestamp)

	log.Debug(ctx, "SSE head event",
		z.U64("slot", slot),
		z.Str("delay", delay.String()),
		z.Str("block", head.Block),
		z.Str("prev_ddr", head.PreviousDutyDependentRoot),
		z.Str("curr_ddr", head.CurrentDutyDependentRoot))

	blockRoot, err := parseRoot(head.Block)
	if err != nil {
		return errors.Wrap(err, "parse head block root", z.Str("addr", p.label(addr)))
	}

	// Invalidate stale duties before head subscribers start an early fetch from them.
	err = p.checkDutiesDependentRoots(ctx, slot, head, addr)
	if err != nil {
		return err
	}

	p.notifyHeadEvent(ctx, eth2p0.Slot(slot), blockRoot, addr)

	return nil
}

// checkDutiesDependentRoots invalidates cached duties whose dependent root differs from the head event's, as if the
// chain reorged back to the epoch before them. A beacon node importing an epoch's last block late serves the next
// epoch's duties from a stale shuffling without any chain_reorg event, while a head event in epoch E reports the
// dependent roots of epoch E (previous) and E+1 (current) attester duties on the chain the node has fully imported.
func (p *listener) checkDutiesDependentRoots(ctx context.Context, slot uint64, head headEventData, addr string) error {
	p.Lock()
	rootFunc := p.dutiesDependentRootFunc
	p.Unlock()

	// Skip if there is no duties cache or the beacon node omitted the duty dependent roots.
	if rootFunc == nil || head.PreviousDutyDependentRoot == "" || head.CurrentDutyDependentRoot == "" {
		return nil
	}

	previous, err := parseRoot(head.PreviousDutyDependentRoot)
	if err != nil {
		return errors.Wrap(err, "parse head previous duty dependent root", z.Str("addr", p.label(addr)))
	}

	current, err := parseRoot(head.CurrentDutyDependentRoot)
	if err != nil {
		return errors.Wrap(err, "parse head current duty dependent root", z.Str("addr", p.label(addr)))
	}

	epoch := eth2p0.Epoch(slot / p.slotsPerEpoch)

	for _, check := range []struct {
		epoch    eth2p0.Epoch
		headRoot eth2p0.Root
	}{
		{epoch: epoch, headRoot: previous},
		{epoch: epoch + 1, headRoot: current},
	} {
		if check.epoch == 0 {
			continue
		}

		cachedRoot, ok := rootFunc(check.epoch)
		if !ok || cachedRoot == check.headRoot {
			continue
		}

		log.Info(ctx, "Cached attester duties dependent root differs from head event, invalidating duties",
			z.U64("epoch", uint64(check.epoch)),
			z.Str("cached_dependent_root", cachedRoot.String()),
			z.Str("head_dependent_root", check.headRoot.String()),
			z.U64("head_slot", slot),
			z.Str("addr", p.label(addr)))
		sseDependentRootMismatchCounter.WithLabelValues(p.label(addr)).Inc()

		// Not deduplicated by epoch like chain_reorg: the refetch may be answered by the lagging node again,
		// in which case the next head event must trigger again.
		p.notifyChainReorg(ctx, check.epoch-1, false)
	}

	return nil
}

func (p *listener) handleChainReorgEvent(ctx context.Context, event *event, addr string) error {
	var chainReorg chainReorgEventData

	err := json.Unmarshal(event.Data, &chainReorg)
	if err != nil {
		return errors.Wrap(err, "unmarshal SSE chain_reorg event", z.Str("addr", p.label(addr)))
	}

	slot, err := strconv.ParseUint(chainReorg.Slot, 10, 64)
	if err != nil {
		return errors.Wrap(err, "parse slot to uint64", z.Str("addr", p.label(addr)))
	}

	depth, err := strconv.ParseUint(chainReorg.Depth, 10, 64)
	if err != nil {
		return errors.Wrap(err, "parse depth to uint64", z.Str("addr", p.label(addr)))
	}

	if slot < depth {
		log.Warn(ctx, "Invalid chain reorg event: depth exceeds slot", nil, z.U64("slot", slot), z.U64("depth", depth))
		return errors.New("invalid chain reorg event: depth exceeds slot")
	}

	reorgEpoch := (slot - depth) / p.slotsPerEpoch
	p.notifyChainReorg(ctx, eth2p0.Epoch(reorgEpoch), true)

	log.Debug(ctx, "SSE chain reorg event",
		z.U64("slot", slot),
		z.Str("epoch", chainReorg.Epoch),
		z.U64("reorg_epoch", reorgEpoch),
		z.U64("depth", depth),
		z.Str("old_head_block", chainReorg.OldHeadBlock),
		z.Str("new_head_block", chainReorg.NewHeadBlock))

	sseChainReorgDepthHistogram.WithLabelValues(p.label(addr)).Observe(float64(depth))

	return nil
}

func (p *listener) handleBlockGossipEvent(ctx context.Context, event *event, addr string) error {
	var blockGossip blockGossipEventData

	err := json.Unmarshal(event.Data, &blockGossip)
	if err != nil {
		return errors.Wrap(err, "unmarshal SSE block_gossip event", z.Str("addr", p.label(addr)))
	}

	slot, err := strconv.ParseUint(blockGossip.Slot, 10, 64)
	if err != nil {
		return errors.Wrap(err, "parse slot to uint64", z.Str("addr", p.label(addr)))
	}

	// Beacon node should receive a block via P2P or API before the attestation due offset.
	delay, ok := p.computeDelay(slot, event.Timestamp, p.blockOnTimeFunc(slot))
	if !ok {
		log.Debug(ctx, "Beacon node received block_gossip event too late", z.U64("slot", slot), z.Str("delay", delay.String()))
	}

	log.Debug(ctx, "SSE block gossip event",
		z.U64("slot", slot),
		z.Str("delay", delay.String()),
		z.Str("block", blockGossip.Block))

	sseBlockGossipHistogram.WithLabelValues(p.label(addr)).Observe(delay.Seconds())

	p.storeBlockGossipTime(slot, addr, event.Timestamp)

	return nil
}

func (p *listener) handleBlockEvent(ctx context.Context, event *event, addr string) error {
	var block blockEventData

	err := json.Unmarshal(event.Data, &block)
	if err != nil {
		return errors.Wrap(err, "unmarshal SSE block event", z.Str("addr", p.label(addr)))
	}

	slot, err := strconv.ParseUint(block.Slot, 10, 64)
	if err != nil {
		return errors.Wrap(err, "parse slot to uint64", z.Str("addr", p.label(addr)))
	}

	// Beacon node should import a block to its fork-choice before the attestation due offset.
	delay, ok := p.computeDelay(slot, event.Timestamp, p.blockOnTimeFunc(slot))
	if !ok {
		log.Debug(ctx, "Beacon node received block event too late", z.U64("slot", slot), z.Str("delay", delay.String()))
	}

	log.Debug(ctx, "SSE block event",
		z.U64("slot", slot),
		z.Str("delay", delay.String()),
		z.Str("block", block.Block))

	sseBlockHistogram.WithLabelValues(p.label(addr)).Observe(delay.Seconds())

	return nil
}

// notifyChainReorg notifies the chain reorg subscribers, skipping a repeat of the last reorg epoch if dedupe is set.
func (p *listener) notifyChainReorg(ctx context.Context, epoch eth2p0.Epoch, dedupe bool) {
	p.Lock()
	defer p.Unlock()

	if dedupe {
		if epoch == p.lastReorgEpoch {
			return
		}

		p.lastReorgEpoch = epoch
	}

	for _, sub := range p.chainReorgSubs {
		sub(ctx, epoch)
	}
}

func (p *listener) notifyHeadEvent(ctx context.Context, slot eth2p0.Slot, blockRoot eth2p0.Root, bnAddr string) {
	p.Lock()
	defer p.Unlock()

	for _, sub := range p.headSubs {
		sub(ctx, slot, blockRoot, bnAddr)
	}
}

// parseRoot parses a 0x-prefixed hex string into an eth2p0.Root.
func parseRoot(hexRoot string) (eth2p0.Root, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(hexRoot, "0x"))
	if err != nil {
		return eth2p0.Root{}, errors.Wrap(err, "decode hex root")
	}

	var root eth2p0.Root
	if len(b) != len(root) {
		return eth2p0.Root{}, errors.New("invalid root length", z.Int("length", len(b)))
	}

	copy(root[:], b)

	return root, nil
}

// computeDelay computes the delay between start of the slot and receiving the event.
// attestationOffset returns the intra slot offset at which attestation data is due for the
// provided slot, before which beacon nodes are expected to have received the slot's block.
// It is a third of the slot pre-gloas and a quarter from the gloas fork onwards.
func (p *listener) attestationOffset(slot uint64) time.Duration {
	return p.slotOffsetFunc(core.Duty{Slot: slot, Type: core.DutyAttester})
}

// blockOnTimeFunc returns a function reporting whether a block related delay is
// within the attestation due offset of the provided slot.
func (p *listener) blockOnTimeFunc(slot uint64) func(time.Duration) bool {
	return func(delay time.Duration) bool {
		return delay < p.attestationOffset(slot)
	}
}

func (p *listener) computeDelay(slot uint64, eventTS time.Time, delayOKFunc func(delay time.Duration) bool) (time.Duration, bool) {
	slotStartTime := p.genesisTime.Add(time.Duration(slot) * p.slotDuration)
	delay := eventTS.Sub(slotStartTime)

	// calculate time of receiving the event - the time of start of the slot
	return delay, delayOKFunc(delay)
}

// storeBlockGossipTime stores the timestamp of a block gossip event for later comparison with head event.
func (p *listener) storeBlockGossipTime(slot uint64, addr string, timestamp time.Time) {
	p.Lock()
	defer p.Unlock()

	if p.blockGossipTimes[slot] == nil {
		p.blockGossipTimes[slot] = make(map[string]time.Time)
	}

	p.blockGossipTimes[slot][addr] = timestamp
}

// recordBlockProcessingTime calculates and records the time between block gossip and head events.
func (p *listener) recordBlockProcessingTime(slot uint64, addr string, headTimestamp time.Time) {
	p.Lock()
	defer p.Unlock()

	addrMap, slotFound := p.blockGossipTimes[slot]
	if !slotFound {
		// Block gossip event not received yet or already cleaned up
		return
	}

	gossipTime, addrFound := addrMap[addr]
	if !addrFound {
		// Block gossip event for this address not received yet or already cleaned up
		return
	}

	processingTime := headTimestamp.Sub(gossipTime)
	if processingTime > 0 {
		sseBlockProcessingTimeHistogram.WithLabelValues(p.label(addr)).Observe(processingTime.Seconds())
	}

	// Clean up this entry as it's no longer needed
	delete(addrMap, addr)

	if len(addrMap) == 0 {
		delete(p.blockGossipTimes, slot)
	}

	// Cleanup old entries (older than one epoch)
	// This handles cases where gossip events don't get matching head events
	if slot > p.slotsPerEpoch {
		cutoff := slot - p.slotsPerEpoch
		for s := range p.blockGossipTimes {
			if s < cutoff {
				delete(p.blockGossipTimes, s)
			}
		}
	}
}
