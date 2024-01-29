// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tracker

import (
	"context"
	"fmt"
	"sync"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

const (
	// InclCheckLag is the number of slots to lag before checking inclusion.
	// We wait for 6 slots to mitigate against reorgs as it should cover almost all reorg scenarios.
	// Reorgs of more than 6 slots are very rare in ethereum PoS.
	// The inclusion checker should begin checking for the inclusion of duties after the duty deadline is reached,
	// i.e., after 5 slots.
	InclCheckLag = 6

	// InclMissedLag is the number of slots after which we assume the duty was not included and we
	// delete cached submissions.
	InclMissedLag = 32
)

// subkey uniquely identifies a submission.
type subkey struct {
	Duty   core.Duty
	Pubkey core.PubKey
}

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
	Slot                   uint64
	AttestationsByDataRoot map[eth2p0.Root]*eth2p0.Attestation
}

// trackerInclFunc defines the tracker callback for the inclusion checker.
type trackerInclFunc func(core.Duty, core.PubKey, core.SignedData, error)

// inclSupported defines duty types for which inclusion checks are supported.
var inclSupported = map[core.DutyType]bool{
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
	submissions map[subkey]submission

	trackerInclFunc trackerInclFunc
	missedFunc      func(context.Context, submission)
	attIncludedFunc func(context.Context, submission, block)
}

// Submitted is called when a duty is submitted to the beacon node.
// It adds the duty to the list of submitted duties.
func (i *inclusionCore) Submitted(duty core.Duty, pubkey core.PubKey, data core.SignedData, delay time.Duration) error {
	if !inclSupported[duty.Type] {
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
		proposal, ok := data.(core.VersionedSignedProposal)
		if !ok {
			return errors.New("invalid block")
		}
		if eth2wrap.IsSyntheticProposal(&proposal.VersionedSignedProposal) {
			// Report inclusion for synthetic blocks as it is already included on-chain.
			i.trackerInclFunc(duty, pubkey, data, nil)

			return nil
		}
	} else if duty.Type == core.DutyBuilderProposer {
		block, ok := data.(core.VersionedSignedBlindedProposal)
		if !ok {
			return errors.New("invalid blinded block")
		}
		if eth2wrap.IsSyntheticBlindedBlock(&block.VersionedSignedBlindedProposal) {
			// Report inclusion for synthetic blinded blocks as it is already included on-chain.
			i.trackerInclFunc(duty, pubkey, data, nil)

			return nil
		}
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	key := subkey{Duty: duty, Pubkey: pubkey}
	i.submissions[key] = submission{
		Duty:        duty,
		Pubkey:      pubkey,
		Data:        data,
		AttDataRoot: attRoot,
		Delay:       delay,
	}

	return nil
}

// Trim removes all duties that are older than the specified slot.
// It also calls the missedFunc for any duties that have not been included.
func (i *inclusionCore) Trim(ctx context.Context, slot uint64) {
	i.mu.Lock()
	defer i.mu.Unlock()

	// Trim submissions
	for key, sub := range i.submissions {
		if sub.Duty.Slot > slot {
			continue
		}

		// Report missed and trim
		i.missedFunc(ctx, sub)
		i.trackerInclFunc(sub.Duty, sub.Pubkey, sub.Data, errors.New("duty not included on-chain"))

		delete(i.submissions, key)
	}
}

// CheckBlock checks whether the block includes any of the submitted duties.
func (i *inclusionCore) CheckBlock(ctx context.Context, block block) {
	i.mu.Lock()
	defer i.mu.Unlock()

	for key, sub := range i.submissions {
		switch sub.Duty.Type {
		case core.DutyAttester:
			ok, err := checkAttestationInclusion(sub, block)
			if err != nil {
				log.Warn(ctx, "Failed to check attestation inclusion", err)
			} else if !ok {
				continue
			}

			// Report inclusion and trim
			i.attIncludedFunc(ctx, sub, block)
			i.trackerInclFunc(sub.Duty, sub.Pubkey, sub.Data, nil)
			delete(i.submissions, key)
		case core.DutyAggregator:
			ok, err := checkAggregationInclusion(sub, block)
			if err != nil {
				log.Warn(ctx, "Failed to check aggregate inclusion", err)
			} else if !ok {
				continue
			}
			// Report inclusion and trim
			i.attIncludedFunc(ctx, sub, block)
			i.trackerInclFunc(sub.Duty, sub.Pubkey, sub.Data, nil)
			delete(i.submissions, key)
		case core.DutyProposer, core.DutyBuilderProposer:
			if sub.Duty.Slot != block.Slot {
				continue
			}

			msg := "Broadcasted block included on-chain"
			if sub.Duty.Type == core.DutyBuilderProposer {
				msg = "Broadcasted blinded block included on-chain"
			}

			log.Info(ctx, msg,
				z.U64("block_slot", block.Slot),
				z.Any("pubkey", sub.Pubkey),
				z.Any("broadcast_delay", sub.Delay),
			)

			// Just report block inclusions to tracker and trim
			i.trackerInclFunc(sub.Duty, sub.Pubkey, sub.Data, nil)
			delete(i.submissions, key)
		default:
			panic("bug: unexpected type") // Sanity check, this should never happen
		}
	}
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

	switch sub.Duty.Type {
	case core.DutyAttester, core.DutyAggregator:
		msg := "Broadcasted attestation never included on-chain"
		if sub.Duty.Type == core.DutyAggregator {
			msg = "Broadcasted attestation aggregate never included on-chain"
		}

		log.Warn(ctx, msg, nil,
			z.Any("pubkey", sub.Pubkey),
			z.U64("attestation_slot", sub.Duty.Slot),
			z.Any("broadcast_delay", sub.Delay),
		)
	case core.DutyProposer, core.DutyBuilderProposer:
		msg := "Broadcasted block never included on-chain"
		if sub.Duty.Type == core.DutyBuilderProposer {
			msg = "Broadcasted blinded block never included on-chain"
		}

		log.Warn(ctx, msg, nil,
			z.Any("pubkey", sub.Pubkey),
			z.U64("block_slot", sub.Duty.Slot),
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
	attSlot := uint64(att.Data.Slot)
	blockSlot := block.Slot
	inclDelay := block.Slot - attSlot

	msg := "Broadcasted attestation included on-chain"
	if sub.Duty.Type == core.DutyAggregator {
		msg = "Broadcasted attestation aggregate included on-chain"
	}

	log.Info(ctx, msg,
		z.U64("block_slot", blockSlot),
		z.U64("attestation_slot", attSlot),
		z.Any("pubkey", sub.Pubkey),
		z.U64("inclusion_delay", inclDelay),
		z.Any("broadcast_delay", sub.Delay),
		z.Int("aggregate_len", len(aggIndices)),
		z.Bool("aggregated", len(aggIndices) > 1),
	)

	inclusionDelay.Set(float64(blockSlot - attSlot))
}

// NewInclusion returns a new InclusionChecker.
func NewInclusion(ctx context.Context, eth2Cl eth2wrap.Client, trackerInclFunc trackerInclFunc) (*InclusionChecker, error) {
	genesis, err := eth2Cl.GenesisTime(ctx)
	if err != nil {
		return nil, err
	}

	eth2Resp, err := eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
	if err != nil {
		return nil, err
	}

	slotDuration, ok := eth2Resp.Data["SECONDS_PER_SLOT"].(time.Duration)
	if !ok {
		return nil, errors.New("fetch slot duration")
	}

	inclCore := &inclusionCore{
		attIncludedFunc: reportAttInclusion,
		missedFunc:      reportMissed,
		trackerInclFunc: trackerInclFunc,
		submissions:     make(map[subkey]submission),
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
func (a *InclusionChecker) Submitted(duty core.Duty, set core.SignedDataSet) error {
	slotStart := a.genesis.Add(a.slotDuration * time.Duration(duty.Slot))

	for key, data := range set {
		if err := a.core.Submitted(duty, key, data, time.Since(slotStart)); err != nil {
			return err
		}
	}

	return nil
}

func (a *InclusionChecker) Run(ctx context.Context) {
	ctx = log.WithTopic(ctx, "tracker")

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var checkedSlot uint64

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			slot := uint64(time.Since(a.genesis)/a.slotDuration) - InclCheckLag
			if checkedSlot == slot {
				continue
			}

			if err := a.checkBlock(ctx, slot); err != nil {
				log.Warn(ctx, "Failed to check inclusion", err, z.U64("slot", slot))
				continue
			}

			checkedSlot = slot
			a.core.Trim(ctx, slot-InclMissedLag)
		}
	}
}

func (a *InclusionChecker) checkBlock(ctx context.Context, slot uint64) error {
	atts, err := a.eth2Cl.BlockAttestations(ctx, fmt.Sprint(slot))
	if err != nil {
		return err
	} else if len(atts) == 0 {
		return nil // No block for this slot
	}

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
