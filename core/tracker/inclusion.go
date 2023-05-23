// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tracker

import (
	"context"
	"encoding/json"
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
	// inclTrimLag is the number of slots after which we delete cached submissions.
	// This matches scheduler trimEpochOffset.
	inclTrimLag = 32 * 3
)

// submission represents a duty submitted to the beacon node/chain.
type submission struct {
	Duty        core.Duty
	Pubkey      core.PubKey
	Data        core.SignedData
	AttDataRoot eth2p0.Root
	Delay       time.Duration
}

// block is a simplified block with its attestations.
type block struct {
	Slot                   int64
	AttestationsByDataRoot map[eth2p0.Root]*eth2p0.Attestation
}

// supported duty types.
var supported = map[core.DutyType]bool{
	core.DutyAttester:        true,
	core.DutyAggregator:      true,
	core.DutyProposer:        true,
	core.DutyBuilderProposer: true,
	// TODO(corver) Add support for sync committee and exit duties
}

// inclusionCore tracks the inclusion of submitted duties.
// It has a simplified API to allow for easy testing.
type inclusionCore struct {
	mu          sync.Mutex
	submissions []submission

	missedFunc      func(context.Context, submission)
	attIncludedFunc func(context.Context, submission, block)
}

// Submitted is called when a duty is submitted to the beacon node.
// It adds the duty to the list of submitted duties.
func (i *inclusionCore) Submitted(duty core.Duty, pubkey core.PubKey, data core.SignedData, delay time.Duration) error {
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
		attRoot, err = att.Data.HashTreeRoot()
		if err != nil {
			return errors.Wrap(err, "hash attestation")
		}
	} else if duty.Type == core.DutyAggregator {
		agg, ok := data.(core.SignedAggregateAndProof)
		if !ok {
			return errors.New("invalid aggregate and proof")
		}
		attRoot, err = agg.Message.Aggregate.Data.HashTreeRoot()
		if err != nil {
			return errors.Wrap(err, "hash aggregate")
		}
	} else if duty.Type == core.DutyProposer {
		block, ok := data.(core.VersionedSignedBeaconBlock)
		if !ok {
			return errors.New("invalid block")
		}
		if eth2wrap.IsSyntheticBlock(&block.VersionedSignedBeaconBlock) {
			return nil
		}
	} else if duty.Type == core.DutyBuilderProposer {
		block, ok := data.(core.VersionedSignedBlindedBeaconBlock)
		if !ok {
			return errors.New("invalid blinded block")
		}
		if eth2wrap.IsSyntheticBlindedBlock(&block.VersionedSignedBlindedBeaconBlock) {
			return nil
		}
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	i.submissions = append(i.submissions, submission{
		Duty:        duty,
		Pubkey:      pubkey,
		Data:        data,
		AttDataRoot: attRoot,
		Delay:       delay,
	})

	return nil
}

// Trim removes all duties that are older than the specified slot.
// It also calls the missedFunc for any duties that have not been included.
func (i *inclusionCore) Trim(ctx context.Context, slot int64) {
	i.mu.Lock()
	defer i.mu.Unlock()

	// Trim submissions
	var remaining []submission
	for _, sub := range i.submissions {
		if sub.Duty.Slot > slot {
			// Keep
			remaining = append(remaining, sub)
			continue
		}

		// Report missed and trim
		i.missedFunc(ctx, sub)
	}
	i.submissions = remaining
}

// CheckBlock checks whether the block includes any of the submitted duties.
func (i *inclusionCore) CheckBlock(ctx context.Context, block block) {
	i.mu.Lock()
	defer i.mu.Unlock()

	var remaining []submission
	for _, sub := range i.submissions {
		switch sub.Duty.Type {
		case core.DutyAttester:
			ok, err := checkAttestationInclusion(sub, block)
			if err != nil {
				log.Warn(ctx, "Failed to check attestation inclusion", err)
			}
			if !ok {
				remaining = append(remaining, sub)
			} else {
				// Report inclusion and trim
				i.attIncludedFunc(ctx, sub, block)
			}
		case core.DutyAggregator:
			ok, err := checkAggregationInclusion(sub, block)
			if err != nil {
				log.Warn(ctx, "Failed to check aggregate inclusion", err)
			}
			if !ok {
				remaining = append(remaining, sub)
			} else {
				// Report inclusion and trim
				i.attIncludedFunc(ctx, sub, block)
			}
		case core.DutyProposer, core.DutyBuilderProposer:
			if sub.Duty.Slot != block.Slot {
				remaining = append(remaining, sub)
				continue
			}

			// Nothing to report for block inclusions, just trim
		default:
			panic("bug: unexpected type") // Sanity check, this should never happen
		}
	}

	i.submissions = remaining
}

// checkAggregationInclusion checks whether the aggregation is included in the block.
func checkAggregationInclusion(sub submission, block block) (bool, error) {
	att, ok := block.AttestationsByDataRoot[sub.AttDataRoot]
	if !ok {
		return false, nil
	}

	subBits := sub.Data.(core.SignedAggregateAndProof).Message.Aggregate.AggregationBits
	ok, err := att.AggregationBits.Contains(subBits)
	if err != nil {
		return false, errors.Wrap(err, "check aggregation bits",
			z.U64("block_bits", att.AggregationBits.Len()),
			z.U64("sub_bits", subBits.Len()),
		)
	}

	return ok, nil
}

// checkAttestationInclusion checks whether the attestation is included in the block.
func checkAttestationInclusion(sub submission, block block) (bool, error) {
	att, ok := block.AttestationsByDataRoot[sub.AttDataRoot]
	if !ok {
		return false, nil
	}

	subBits := sub.Data.(core.Attestation).AggregationBits
	ok, err := att.AggregationBits.Contains(subBits)
	if err != nil {
		return false, errors.Wrap(err, "check aggregation bits",
			z.U64("block_bits", att.AggregationBits.Len()),
			z.U64("sub_bits", subBits.Len()),
		)
	}

	return ok, nil
}

// reportMissed reports duties that were broadcast but never included on chain.
func reportMissed(ctx context.Context, sub submission) {
	inclusionMisses.WithLabelValues(sub.Duty.Type.String()).Inc()

	// TODO(corver): Remove debug logs for https://github.com/ObolNetwork/charon/issues/2130
	b, _ := json.Marshal(sub) //nolint:errchkjson
	log.Debug(ctx, "Debug missed submission details",
		z.Any("pubkey", sub.Pubkey),
		z.Any("duty", sub.Duty),
		z.Hex("submission", b),
	)

	switch sub.Duty.Type {
	case core.DutyAttester, core.DutyAggregator:
		msg := "Broadcasted attestation never included on-chain"
		if sub.Duty.Type == core.DutyAggregator {
			msg = "Broadcasted attestation aggregate never included on-chain"
		}

		log.Warn(ctx, msg, nil,
			z.Any("pubkey", sub.Pubkey),
			z.I64("attestation_slot", sub.Duty.Slot),
			z.Any("broadcast_delay", sub.Delay),
		)
	case core.DutyProposer, core.DutyBuilderProposer:
		msg := "Broadcasted block never included on-chain"
		if sub.Duty.Type == core.DutyBuilderProposer {
			msg = "Broadcasted blinded block never included on-chain"
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

// reportAttInclusion reports attestations that were included in a block.
func reportAttInclusion(ctx context.Context, sub submission, block block) {
	att := block.AttestationsByDataRoot[sub.AttDataRoot]
	aggIndices := att.AggregationBits.BitIndices()
	attSlot := int64(att.Data.Slot)
	blockSlot := block.Slot
	inclDelay := block.Slot - attSlot

	msg := "Broadcasted attestation included on-chain"
	if sub.Duty.Type == core.DutyAggregator {
		msg = "Broadcasted attestation aggregate included on-chain"
	}

	log.Info(ctx, msg,
		z.I64("block_slot", blockSlot),
		z.I64("attestation_slot", attSlot),
		z.Any("pubkey", sub.Pubkey),
		z.I64("inclusion_delay", inclDelay),
		z.Any("broadcast_delay", sub.Delay),
		z.Int("aggregate_len", len(aggIndices)),
		z.Bool("aggregated", len(aggIndices) > 1),
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

	inclCore := &inclusionCore{
		attIncludedFunc: reportAttInclusion,
		missedFunc:      reportMissed,
	}

	return &InclusionChecker{
		core:           inclCore,
		eth2Cl:         eth2Cl,
		genesis:        genesis,
		slotDuration:   slotDuration,
		checkBlockFunc: inclCore.CheckBlock,
	}, nil
}

// InclusionChecker checks whether duties have been included on-chain.
type InclusionChecker struct {
	genesis        time.Time
	slotDuration   time.Duration
	eth2Cl         eth2wrap.Client
	core           *inclusionCore
	checkBlockFunc func(context.Context, block) // Alises for testing
}

// Submitted is called when a duty has been submitted.
func (a *InclusionChecker) Submitted(duty core.Duty, pubkey core.PubKey, data core.SignedData) error {
	slotStart := a.genesis.Add(a.slotDuration * time.Duration(duty.Slot))
	return a.core.Submitted(duty, pubkey, data, time.Since(slotStart))
}

func (a *InclusionChecker) Run(ctx context.Context) {
	ctx = log.WithTopic(ctx, "tracker")

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var checkedSlot int64

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			slot := int64(time.Since(a.genesis)/a.slotDuration) - inclCheckLag
			if checkedSlot == slot || slot < 0 {
				continue
			}

			if err := a.checkBlock(ctx, slot); err != nil {
				log.Warn(ctx, "Failed to check inclusion", err, z.I64("slot", slot))
				continue
			}

			checkedSlot = slot
			a.core.Trim(ctx, slot-inclTrimLag)
		}
	}
}

func (a *InclusionChecker) checkBlock(ctx context.Context, slot int64) error {
	atts, err := a.eth2Cl.BlockAttestations(ctx, fmt.Sprint(slot))
	if err != nil {
		return err
	} else if len(atts) == 0 {
		// TODO(corver): Remove this log, its probably too verbose
		log.Debug(ctx, "Skipping missed block inclusion check", z.I64("slot", slot))
		return nil // No block for this slot
	}

	// TODO(corver): Remove this log, its probably too verbose
	log.Debug(ctx, "Checking block inclusion", z.I64("slot", slot))

	// Map attestations by data root, merging duplicates (with identical attestation data).
	attsMap := make(map[eth2p0.Root]*eth2p0.Attestation)
	for _, att := range atts {
		if att == nil || att.Data == nil {
			return errors.New("invalid attestation")
		}

		if att.Data.Target == nil || att.Data.Source == nil {
			return errors.New("invalid attestation data checkpoint")
		}

		root, err := att.Data.HashTreeRoot()
		if err != nil {
			return errors.Wrap(err, "hash attestation")
		}

		// Zero signature since it isn't used and wouldn't be valid after merging anyway.
		att.Signature = eth2p0.BLSSignature{}

		if exist, ok := attsMap[root]; ok {
			// Merge duplicate attestations (only aggregation bits)
			att.AggregationBits, err = att.AggregationBits.Or(exist.AggregationBits)
			if err != nil {
				return errors.Wrap(err, "merge attestation aggregation bits")
			}
		}

		attsMap[root] = att
	}

	a.checkBlockFunc(ctx, block{Slot: slot, AttestationsByDataRoot: attsMap})

	return nil
}
