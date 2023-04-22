// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tracker

import (
	"context"
	"fmt"
	"sync"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

const (
	// inclCheckLag is the number of slots to lag before checking inclusion.
	// Half an epoch is good compromise between finality and responsiveness.
	inclCheckLag = 16
	// trimEpochOffset is the number of epochs after which we delete cached submissions.
	// This matches scheduler trimEpochOffset.
	trimEpochOffset = 3
)

// submission represents a duty submitted to the beacon node/chain.
type submission struct {
	Duty     core.Duty
	Pubkey   core.PubKey
	Data     core.SignedData
	AttRoot  eth2p0.Root
	Delay    time.Duration
	Included bool
}

// block is a simplified block with its attestations.
type block struct {
	Slot         int64
	Attestations map[eth2p0.Root]*eth2p0.Attestation
}

// supported duty types.
var supported = map[core.DutyType]bool{
	core.DutyAttester:        true,
	core.DutyAggregator:      true,
	core.DutyProposer:        true,
	core.DutyBuilderProposer: true,
	// TODO(corver) Add support for sync committee and exit duties
}

// inclusion tracks the inclusion of submitted duties.
// It has a simplified API to allow for easy testing.
type inclusion struct {
	mu          sync.Mutex
	submissions []submission

	missedFunc      func(context.Context, submission)
	attIncludedFunc func(context.Context, submission, block)
}

// Submitted is called when a duty is submitted to the beacon node.
// It adds the duty to the list of submitted duties.
func (i *inclusion) Submitted(duty core.Duty, pubkey core.PubKey, data core.SignedData, delay time.Duration) error {
	if !supported[duty.Type] {
		return nil
	}

	var (
		attRoot eth2p0.Root
		err     error
	)
	if duty.Type == core.DutyAttester {
		att, ok := data.(core.Attestation)
		if !ok {
			return errors.New("invalid attestation")
		}
		attRoot, err = att.HashTreeRoot()
		if err != nil {
			return errors.Wrap(err, "hash attestation")
		}
	} else if duty.Type == core.DutyAggregator {
		agg, ok := data.(core.SignedAggregateAndProof)
		if !ok {
			return errors.New("invalid aggregate and proof")
		}
		attRoot, err = agg.Message.Aggregate.HashTreeRoot()
		if err != nil {
			return errors.Wrap(err, "hash aggregate")
		}
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	i.submissions = append(i.submissions, submission{
		Duty:    duty,
		Pubkey:  pubkey,
		Data:    data,
		AttRoot: attRoot,
		Delay:   delay,
	})

	return nil
}

// Trim removes all duties that are older than the specified slot.
// It also calls the missedFunc for any duties that have not been included.
func (i *inclusion) Trim(ctx context.Context, slot int64) {
	i.mu.Lock()
	defer i.mu.Unlock()

	var remaining []submission
	for _, sub := range i.submissions {
		if sub.Duty.Slot > slot {
			remaining = append(remaining, sub)
			continue
		}
		if !sub.Included {
			i.missedFunc(ctx, sub)
		}
	}
	i.submissions = remaining
}

// CheckBlock checks whether the block includes any of the submitted duties.
func (i *inclusion) CheckBlock(ctx context.Context, block block) {
	i.mu.Lock()
	defer i.mu.Unlock()

	for j, sub := range i.submissions {
		if sub.Included {
			continue
		}

		switch sub.Duty.Type {
		case core.DutyAttester, core.DutyAggregator:
			_, ok := block.Attestations[sub.AttRoot]
			if !ok {
				continue
			}
			i.submissions[j].Included = true
			i.attIncludedFunc(ctx, sub, block)
		case core.DutyProposer, core.DutyBuilderProposer:
			if sub.Duty.Slot != block.Slot {
				continue
			}
			i.submissions[j].Included = true
			// Nothing to report for block inclusions
		default:
			panic("bug: unexpected type") // Sanity check, this should never happen
		}
	}
}

// reportMissed reports duties that were broadcast but never included on chain.
func reportMissed(ctx context.Context, sub submission) {
	inclusionMisses.WithLabelValues(sub.Duty.Type.String()).Inc()

	switch sub.Duty.Type {
	case core.DutyAttester, core.DutyAggregator:
		msg := "Broadcasted attestation never included in any block"
		if sub.Duty.Type == core.DutyAggregator {
			msg = "Broadcasted attestation aggregate never included in any block"
		}

		log.Warn(ctx, msg, nil,
			z.Any("pubkey", sub.Pubkey),
			z.I64("attestation_slot", sub.Duty.Slot),
			z.Any("broadcast_delay", sub.Delay),
		)
	case core.DutyProposer, core.DutyBuilderProposer:
		msg := "Broadcasted block never included in the chain"
		if sub.Duty.Type == core.DutyBuilderProposer {
			msg = "Broadcasted blinded block never included in the chain"
		}

		log.Warn(ctx, msg, nil,
			z.Any("pubkey", sub.Pubkey),
			z.I64("block_slot", sub.Duty.Slot),
			z.Any("broadcast_delay", sub.Delay),
		)
	default:
		panic("bug: unexpected type") // Sanity check, this should never happen
	}
}

func reportAttInclusion(ctx context.Context, sub submission, block block) {
	blockSlot := block.Slot
	attSlot := int64(block.Attestations[sub.AttRoot].Data.Slot)
	inclDelay := block.Slot - attSlot

	msg := "Block included attestation"
	if sub.Duty.Type == core.DutyAggregator {
		msg += " aggregate"
	}

	log.Info(ctx, msg,
		z.I64("block_slot", blockSlot),
		z.I64("attestation_slot", attSlot),
		z.Any("pubkey", sub.Pubkey),
		z.I64("inclusion_delay", inclDelay),
		z.Any("broadcast_delay", sub.Delay),
	)

	inclusionDelay.Set(float64(blockSlot - attSlot))
}

// NewInclusion returns a new InclusionChecker.
func NewInclusion(ctx context.Context, eth2Cl eth2wrap.Client) (*InclusionChecker, error) {
	genesis, err := eth2Cl.GenesisTime(ctx)
	if err != nil {
		return nil, err
	}

	slotDuration, err := eth2Cl.SlotDuration(ctx)
	if err != nil {
		return nil, err
	}

	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return nil, err
	}

	return &InclusionChecker{
		incl: &inclusion{
			attIncludedFunc: reportAttInclusion,
			missedFunc:      reportMissed,
		},
		eth2Cl:        eth2Cl,
		genesis:       genesis,
		slotDuration:  slotDuration,
		slotsPerEpoch: int64(slotsPerEpoch),
	}, nil
}

// InclusionChecker checks whether duties have been included in blocks.
type InclusionChecker struct {
	genesis       time.Time
	slotDuration  time.Duration
	slotsPerEpoch int64
	eth2Cl        eth2wrap.Client
	incl          *inclusion
}

// Submitted is called when a duty has been submitted.
func (a *InclusionChecker) Submitted(duty core.Duty, pubkey core.PubKey, data core.SignedData) error {
	slotStart := a.genesis.Add(a.slotDuration * time.Duration(duty.Slot))
	return a.incl.Submitted(duty, pubkey, data, time.Since(slotStart))
}

func (a *InclusionChecker) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var checkedSlot int64

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			slot := int64(time.Since(a.genesis)/a.slotDuration) - inclCheckLag
			if checkedSlot == slot {
				continue
			} else if checkedSlot != 0 && checkedSlot+1 != slot {
				slot = checkedSlot + 1 // We missed a slot, check the next one first
			}

			if err := a.checkBlock(ctx, slot); err != nil {
				log.Warn(ctx, "Failed to check inclusion", err, z.I64("slot", slot))
				continue
			}

			checkedSlot = slot
			a.incl.Trim(ctx, slot-(trimEpochOffset*a.slotsPerEpoch))
		}
	}
}

func (a *InclusionChecker) checkBlock(ctx context.Context, slot int64) error {
	atts, err := a.eth2Cl.BlockAttestations(ctx, fmt.Sprint(slot))
	if err != nil {
		return err
	} else if len(atts) == 0 {
		return nil // No block for this slot
	}

	attsMap := make(map[eth2p0.Root]*eth2p0.Attestation)
	for _, att := range atts {
		root, err := att.HashTreeRoot()
		if err != nil {
			return errors.Wrap(err, "hash attestation")
		}

		attsMap[root] = att
	}

	a.incl.CheckBlock(ctx, block{Slot: slot, Attestations: attsMap})

	return nil
}
