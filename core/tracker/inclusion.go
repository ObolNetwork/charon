// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tracker

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/statecomm"
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

// blockV2 is a simplified block with its v2 attestations.
type blockV2 struct {
	Slot                   uint64
	AttestationsByDataRoot map[eth2p0.Root]*eth2spec.VersionedAttestation
	BeaconCommitees        []*statecomm.StateCommittee
}

// attCommittee is a versioned attestation with its aggregation bits mapped to the respective beacon committee
type attCommittee struct {
	Attestation           *eth2spec.VersionedAttestation
	CommitteeAggregations map[eth2p0.CommitteeIndex]bitfield.Bitlist
}

// trackerInclFunc defines the tracker callback for the inclusion checker.
type trackerInclFunc func(core.Duty, core.PubKey, core.SignedData, error)

// inclSupported defines duty types for which inclusion checks are supported.
var inclSupported = map[core.DutyType]bool{
	core.DutyAttester:   true,
	core.DutyAggregator: true,
	core.DutyProposer:   true,
	// TODO(corver) Add support for sync committee and exit duties
}

// inclusionCore tracks the inclusion of submitted duties.
// It has a simplified API to allow for easy testing.
type inclusionCore struct {
	mu          sync.Mutex
	submissions map[subkey]submission

	trackerInclFunc   trackerInclFunc
	missedFunc        func(context.Context, submission)
	attIncludedFunc   func(context.Context, submission, block)
	attV2IncludedFunc func(context.Context, submission, blockV2)
}

// Submitted is called when a duty is submitted to the beacon node.
// It adds the duty to the list of submitted duties.
func (i *inclusionCore) Submitted(duty core.Duty, pubkey core.PubKey, data core.SignedData, delay time.Duration) (err error) {
	if !inclSupported[duty.Type] {
		return nil
	}

	var attRoot eth2p0.Root
	if duty.Type == core.DutyAttester {
		att, ok := data.(core.VersionedAttestation)
		if ok {
			attData, err := att.Data()
			if err != nil {
				return errors.Wrap(err, "get attestation data")
			}
			attRoot, err = attData.HashTreeRoot()
			if err != nil {
				return errors.Wrap(err, "hash attestation")
			}
		} else {
			att, ok := data.(core.Attestation)
			if !ok {
				return errors.New("invalid attestation")
			}
			attRoot, err = att.Data.HashTreeRoot()
			if err != nil {
				return errors.Wrap(err, "hash attestation")
			}
		}
	} else if duty.Type == core.DutyAggregator {
		agg, ok := data.(core.VersionedSignedAggregateAndProof)
		if ok {
			attRoot, err = agg.Data().HashTreeRoot()
			if err != nil {
				return errors.Wrap(err, "hash aggregate")
			}
		} else {
			agg, ok := data.(core.SignedAggregateAndProof)
			if !ok {
				return errors.New("invalid aggregate and proof")
			}
			attRoot, err = agg.Message.Aggregate.Data.HashTreeRoot()
			if err != nil {
				return errors.Wrap(err, "hash aggregate")
			}
		}
	} else if duty.Type == core.DutyProposer {
		var (
			block core.VersionedSignedProposal
			ok    bool
		)

		block, ok = data.(core.VersionedSignedProposal)
		if !ok {
			return errors.New("invalid block")
		}

		defer func() {
			if r := recover(); r != nil {
				err = errors.New("could not determine if proposal was synthetic or not",
					z.Str("proposal", fmt.Sprintf("%+v", block)),
					z.Bool("blinded", block.Blinded),
				)
			}
		}()

		switch block.Blinded {
		case true:
			blinded, err := block.ToBlinded()
			if err != nil {
				return errors.Wrap(err, "expected blinded proposal")
			}

			if eth2wrap.IsSyntheticBlindedBlock(&blinded) {
				// Report inclusion for synthetic blocks as it is already included on-chain.
				i.trackerInclFunc(duty, pubkey, data, nil)

				return nil
			}
		default:
			if eth2wrap.IsSyntheticProposal(&block.VersionedSignedProposal) {
				// Report inclusion for synthetic blocks as it is already included on-chain.
				i.trackerInclFunc(duty, pubkey, data, nil)

				return nil
			}
		}
	} else if duty.Type == core.DutyBuilderProposer {
		return core.ErrDeprecatedDutyBuilderProposer
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

	return err
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
		case core.DutyProposer:
			if sub.Duty.Slot != block.Slot {
				continue
			}

			proposal, ok := sub.Data.(core.VersionedSignedProposal)
			if !ok {
				log.Error(ctx, "Submission data has wrong type", nil, z.Str("type", fmt.Sprintf("%T", sub.Data)))
				continue
			}

			msg := "Broadcasted block included on-chain"
			if proposal.Blinded {
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

// CheckBlockV2 checks whether the block includes any of the submitted duties.
func (i *inclusionCore) CheckBlockV2(ctx context.Context, block blockV2) {
	i.mu.Lock()
	defer i.mu.Unlock()

	for key, sub := range i.submissions {
		switch sub.Duty.Type {
		case core.DutyAttester:
			ok, err := checkAttestationV2Inclusion(sub, block)
			if err != nil {
				log.Warn(ctx, "Failed to check attestation inclusion", err)
			} else if !ok {
				continue
			}

			// Report inclusion and trim
			i.attV2IncludedFunc(ctx, sub, block)
			i.trackerInclFunc(sub.Duty, sub.Pubkey, sub.Data, nil)
			delete(i.submissions, key)
		case core.DutyAggregator:
			ok, err := checkAggregationV2Inclusion(sub, block)
			if err != nil {
				log.Warn(ctx, "Failed to check aggregate inclusion", err)
			} else if !ok {
				continue
			}
			// Report inclusion and trim
			i.attV2IncludedFunc(ctx, sub, block)
			i.trackerInclFunc(sub.Duty, sub.Pubkey, sub.Data, nil)
			delete(i.submissions, key)
		case core.DutyProposer:
			if sub.Duty.Slot != block.Slot {
				continue
			}

			proposal, ok := sub.Data.(core.VersionedSignedProposal)
			if !ok {
				log.Error(ctx, "Submission data has wrong type", nil, z.Str("type", fmt.Sprintf("%T", sub.Data)))
				continue
			}

			msg := "Broadcasted block included on-chain"
			if proposal.Blinded {
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

	signedAggProof, ok := sub.Data.(core.SignedAggregateAndProof)
	if !ok {
		return false, errors.New("parse SignedAggregateAndProof")
	}
	subBits := signedAggProof.Message.Aggregate.AggregationBits
	ok, err := att.AggregationBits.Contains(subBits)
	if err != nil {
		return false, errors.Wrap(err, "check aggregation bits",
			z.U64("block_bits", att.AggregationBits.Len()),
			z.U64("sub_bits", subBits.Len()),
		)
	}

	return ok, nil
}

// checkAggregationV2Inclusion checks whether the aggregation is included in the block.
func checkAggregationV2Inclusion(sub submission, block blockV2) (bool, error) {
	att, ok := block.AttestationsByDataRoot[sub.AttDataRoot]
	if !ok {
		return false, nil
	}

	attAggregationBits, err := att.AggregationBits()
	if err != nil {
		return false, errors.Wrap(err, "get attestation aggregation bits")
	}
	signedAggAndProof, ok := sub.Data.(core.VersionedSignedAggregateAndProof)
	if !ok {
		return false, errors.New("parse VersionedSignedAggregateAndProof")
	}

	subBits := signedAggAndProof.AggregationBits()
	ok, err = attAggregationBits.Contains(subBits)
	if err != nil {
		return false, errors.Wrap(err, "check aggregation bits",
			z.U64("block_bits", attAggregationBits.Len()),
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

	coreAtt, ok := sub.Data.(core.Attestation)
	if !ok {
		return false, errors.New("parse Attestation")
	}
	subBits := coreAtt.AggregationBits
	ok, err := att.AggregationBits.Contains(subBits)
	if err != nil {
		return false, errors.Wrap(err, "check aggregation bits",
			z.U64("block_bits", att.AggregationBits.Len()),
			z.U64("sub_bits", subBits.Len()),
		)
	}

	return ok, nil
}

// checkAttestationV2Inclusion checks whether the attestation is included in the block.
func checkAttestationV2Inclusion(sub submission, block blockV2) (bool, error) {
	att, ok := block.AttestationsByDataRoot[sub.AttDataRoot]
	if !ok {
		return false, nil
	}
	attAggBits, err := att.AggregationBits()
	if err != nil {
		return false, errors.Wrap(err, "get attestation aggregation bits")
	}

	subData, ok := sub.Data.(core.VersionedAttestation)
	if !ok {
		return false, errors.New("invalid attestation")
	}
	subAggBits, err := subData.AggregationBits()
	if err != nil {
		return false, errors.Wrap(err, "get attestation aggregation bits")
	}
	if len(subAggBits.BitIndices()) != 1 {
		return false, errors.New("unexpected number of aggregation bits")
	}
	subAggIdx := subAggBits.BitIndices()[0]
	subCommIdx, err := subData.CommitteeIndex()
	if err != nil {
		return false, errors.Wrap(err, "get committee index")
	}

	// Calculate the length of validators of committees before the committee index of the submitted attestation.
	previousCommsValidatorsLen := 0
	for idx := range subCommIdx {
		previousCommsValidatorsLen += len(block.BeaconCommitees[idx].Validators)
	}

	// Previous committees validators length + validator index in attestation committee gives the index of the attestation in the full agreggation bits bitlist.
	return attAggBits.BitAt(uint64(previousCommsValidatorsLen) + uint64(subAggIdx)), nil
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
	case core.DutyProposer:
		proposal, ok := sub.Data.(core.VersionedSignedProposal)
		if !ok {
			log.Error(ctx, "Submission data has wrong type", nil, z.Str("type", fmt.Sprintf("%T", sub.Data)))
		} else {
			msg := "Broadcasted block never included on-chain"
			if proposal.Blinded {
				msg = "Broadcasted blinded block never included on-chain"
			}

			log.Warn(ctx, msg, nil,
				z.Any("pubkey", sub.Pubkey),
				z.U64("block_slot", sub.Duty.Slot),
				z.Any("broadcast_delay", sub.Delay),
			)
		}
	default:
		panic("bug: unexpected type") // Sanity check, this should never happen
	}
}

// reportAttV2Inclusion reports attestations that were included in a block.
func reportAttV2Inclusion(ctx context.Context, sub submission, block blockV2) {
	att := block.AttestationsByDataRoot[sub.AttDataRoot]
	attAggregationBits, err := att.AggregationBits()
	if err != nil {
		return
	}
	aggIndices := attAggregationBits.BitIndices()
	attData, err := att.Data()
	if err != nil {
		return
	}
	attSlot := uint64(attData.Slot)
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
		attIncludedFunc:   reportAttInclusion,
		attV2IncludedFunc: reportAttV2Inclusion,
		missedFunc:        reportMissed,
		trackerInclFunc:   trackerInclFunc,
		submissions:       make(map[subkey]submission),
	}

	return &InclusionChecker{
		core:             inclCore,
		eth2Cl:           eth2Cl,
		genesis:          genesis,
		slotDuration:     slotDuration,
		checkBlockFunc:   inclCore.CheckBlock,
		checkBlockV2Func: inclCore.CheckBlockV2,
	}, nil
}

// InclusionChecker checks whether duties have been included on-chain.
type InclusionChecker struct {
	genesis          time.Time
	slotDuration     time.Duration
	eth2Cl           eth2wrap.Client
	core             *inclusionCore
	checkBlockFunc   func(context.Context, block)   // Alises for testing
	checkBlockV2Func func(context.Context, blockV2) // Alises for testing
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
	attsV2, err := a.eth2Cl.BlockAttestationsV2(ctx, strconv.FormatUint(slot, 10))
	if err != nil {
		if errors.Is(err, eth2wrap.ErrEndpointNotFound) {
			atts, err := a.eth2Cl.BlockAttestations(ctx, strconv.FormatUint(slot, 10))
			if err != nil {
				return err
			} else if len(atts) == 0 {
				return nil
			}

			return a.checkBlockAtts(ctx, slot, atts)
		}

		return err
	} else if len(attsV2) == 0 {
		return nil // No block for this slot
	}

	return a.checkBlockAttsV2(ctx, slot, attsV2)
}

func (a *InclusionChecker) checkBlockAtts(ctx context.Context, slot uint64, atts []*eth2p0.Attestation) error {
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

func (a *InclusionChecker) checkBlockAttsV2(ctx context.Context, slot uint64, atts []*eth2spec.VersionedAttestation) error {
	// Get the slot for which the attestations in the current slot are.
	// This is usually the previous slot, except when the previous is a missed proposal.
	attestation0Data, err := atts[0].Data()
	if err != nil {
		return err
	}
	attestedSlot := attestation0Data.Slot

	// Get the beacon committee for the above mentioned slot.
	committeesForState, err := a.eth2Cl.BeaconStateCommittees(ctx, uint64(attestedSlot))
	if err != nil {
		return err
	}

	// Map attestations by data root, merging duplicates' aggregation bits.
	attsCommitteesMap := make(map[eth2p0.Root]*attCommittee)
	for _, att := range atts {
		if att == nil {
			return errors.New("invalid attestation")
		}

		attData, err := att.Data()
		if err != nil {
			return errors.Wrap(err, "invalid attestation data")
		}
		if attData.Target == nil || attData.Source == nil {
			return errors.New("invalid attestation data checkpoint")
		}

		root, err := attData.HashTreeRoot()
		if err != nil {
			return errors.Wrap(err, "hash attestation")
		}

		// Zero signature since it isn't used and wouldn't be valid after merging anyway.
		err = setAttestationSignature(*att, eth2p0.BLSSignature{})
		if err != nil {
			return err
		}

		attCommittee := &attCommittee{
			Attestation: att,
		}
		committeeAggregations, err := conjugateAggregationBits(attCommittee, attsCommitteesMap, root, committeesForState)
		if err != nil {
			return err
		}
		attCommittee.CommitteeAggregations = committeeAggregations
		attsCommitteesMap[root] = attCommittee
	}

	attsMap := make(map[eth2p0.Root]*eth2spec.VersionedAttestation)
	for root, att := range attsCommitteesMap {
		unwrapedAtt := att.Attestation
		if att.CommitteeAggregations != nil {
			aggBits := bitfield.Bitlist{}
			for _, commBits := range att.CommitteeAggregations {
				aggBits = append(aggBits, commBits...)
			}
			err = setAttestationAggregationBits(*unwrapedAtt, aggBits)
			if err != nil {
				return err
			}
		}
		attsMap[root] = unwrapedAtt
	}

	a.checkBlockV2Func(ctx, blockV2{Slot: slot, AttestationsByDataRoot: attsMap, BeaconCommitees: committeesForState})

	return nil
}

func setAttestationSignature(att eth2spec.VersionedAttestation, sig eth2p0.BLSSignature) error {
	switch att.Version {
	case eth2spec.DataVersionPhase0:
		if att.Phase0 == nil {
			return errors.New("no Phase0 attestation")
		}
		att.Phase0.Signature = sig

		return nil
	case eth2spec.DataVersionAltair:
		if att.Altair == nil {
			return errors.New("no Altair attestation")
		}
		att.Altair.Signature = sig

		return nil
	case eth2spec.DataVersionBellatrix:
		if att.Bellatrix == nil {
			return errors.New("no Bellatrix attestation")
		}
		att.Bellatrix.Signature = sig

		return nil
	case eth2spec.DataVersionCapella:
		if att.Capella == nil {
			return errors.New("no Capella attestation")
		}
		att.Capella.Signature = sig

		return nil
	case eth2spec.DataVersionDeneb:
		if att.Deneb == nil {
			return errors.New("no Deneb attestation")
		}
		att.Deneb.Signature = sig

		return nil
	case eth2spec.DataVersionElectra:
		if att.Electra == nil {
			return errors.New("no Electra attestation")
		}
		att.Electra.Signature = sig

		return nil
	default:
		return errors.New("unknown attestation version", z.Str("version", att.Version.String()))
	}
}

func setAttestationAggregationBits(att eth2spec.VersionedAttestation, bits bitfield.Bitlist) error {
	switch att.Version {
	case eth2spec.DataVersionPhase0:
		if att.Phase0 == nil {
			return errors.New("no Phase0 attestation")
		}
		att.Phase0.AggregationBits = bits

		return nil
	case eth2spec.DataVersionAltair:
		if att.Altair == nil {
			return errors.New("no Altair attestation")
		}
		att.Altair.AggregationBits = bits

		return nil
	case eth2spec.DataVersionBellatrix:
		if att.Bellatrix == nil {
			return errors.New("no Bellatrix attestation")
		}
		att.Bellatrix.AggregationBits = bits

		return nil
	case eth2spec.DataVersionCapella:
		if att.Capella == nil {
			return errors.New("no Capella attestation")
		}
		att.Capella.AggregationBits = bits

		return nil
	case eth2spec.DataVersionDeneb:
		if att.Deneb == nil {
			return errors.New("no Deneb attestation")
		}
		att.Deneb.AggregationBits = bits

		return nil
	case eth2spec.DataVersionElectra:
		if att.Electra == nil {
			return errors.New("no Electra attestation")
		}
		att.Electra.AggregationBits = bits

		return nil
	default:
		return errors.New("unknown attestation version", z.Str("version", att.Version.String()))
	}
}

func conjugateAggregationBits(att *attCommittee, attsMap map[eth2p0.Root]*attCommittee, root eth2p0.Root, committeesForState []*statecomm.StateCommittee) (map[eth2p0.CommitteeIndex]bitfield.Bitlist, error) {
	switch att.Attestation.Version {
	case eth2spec.DataVersionPhase0:
		if att.Attestation.Phase0 == nil {
			return nil, errors.New("no Phase0 attestation")
		}

		return nil, conjugateAggregationBitsPhase0(att, attsMap, root)
	case eth2spec.DataVersionAltair:
		if att.Attestation.Altair == nil {
			return nil, errors.New("no Altair attestation")
		}

		return nil, conjugateAggregationBitsPhase0(att, attsMap, root)
	case eth2spec.DataVersionBellatrix:
		if att.Attestation.Bellatrix == nil {
			return nil, errors.New("no Bellatrix attestation")
		}

		return nil, conjugateAggregationBitsPhase0(att, attsMap, root)
	case eth2spec.DataVersionCapella:
		if att.Attestation.Capella == nil {
			return nil, errors.New("no Capella attestation")
		}

		return nil, conjugateAggregationBitsPhase0(att, attsMap, root)
	case eth2spec.DataVersionDeneb:
		if att.Attestation.Deneb == nil {
			return nil, errors.New("no Deneb attestation")
		}

		return nil, conjugateAggregationBitsPhase0(att, attsMap, root)
	case eth2spec.DataVersionElectra:
		if att.Attestation.Electra == nil {
			return nil, errors.New("no Electra attestation")
		}

		return conjugateAggregationBitsElectra(att, attsMap, root, committeesForState)
	default:
		return nil, errors.New("unknown attestation version", z.Str("version", att.Attestation.Version.String()))
	}
}

func conjugateAggregationBitsPhase0(att *attCommittee, attsMap map[eth2p0.Root]*attCommittee, root eth2p0.Root) error {
	attAggregationBits, err := att.Attestation.AggregationBits()
	if err != nil {
		return errors.Wrap(err, "get attestation aggregation bits")
	}

	if exist, ok := attsMap[root]; ok {
		existAttAggregationBits, err := exist.Attestation.AggregationBits()
		if err != nil {
			return errors.Wrap(err, "get attestation aggregation bits")
		}
		// Merge duplicate attestations (only aggregation bits).
		bits, err := attAggregationBits.Or(existAttAggregationBits)
		if err != nil {
			return errors.Wrap(err, "merge attestation aggregation bits")
		}
		err = setAttestationAggregationBits(*att.Attestation, bits)
		if err != nil {
			return errors.Wrap(err, "set attestation aggregation bits")
		}
	}

	return nil
}

func conjugateAggregationBitsElectra(att *attCommittee, attsMap map[eth2p0.Root]*attCommittee, root eth2p0.Root, committeesForState []*statecomm.StateCommittee) (map[eth2p0.CommitteeIndex]bitfield.Bitlist, error) {
	fullAttestationAggregationBits, err := att.Attestation.AggregationBits()
	if err != nil {
		return nil, err
	}
	committeeBits, err := att.Attestation.CommitteeBits()
	if err != nil {
		return nil, err
	}

	var updated map[eth2p0.CommitteeIndex]bitfield.Bitlist
	if exist, ok := attsMap[root]; ok {
		updated = updateAggregationBits(committeeBits, exist.CommitteeAggregations, fullAttestationAggregationBits)
	} else {
		// Create new empty map of committee indices and aggregations per committee.
		attsAggBits := make(map[eth2p0.CommitteeIndex]bitfield.Bitlist)
		// Create a 0'ed bitlist of aggregations of size the amount of validators for all committees.
		for _, comm := range committeesForState {
			attsAggBits[comm.Index] = bitfield.NewBitlist(uint64(len(comm.Validators)))
		}

		updated = updateAggregationBits(committeeBits, attsAggBits, fullAttestationAggregationBits)
	}

	return updated, nil
}

func updateAggregationBits(committeeBits bitfield.Bitvector64, committeeAggregation map[eth2p0.CommitteeIndex]bitfield.Bitlist, fullAttestationAggregationBits bitfield.Bitlist) map[eth2p0.CommitteeIndex]bitfield.Bitlist {
	offset := uint64(0)
	// Iterate over all committees that attested in the current attestation object.
	for _, committeeIndex := range committeeBits.BitIndices() {
		validatorsInCommittee := committeeAggregation[eth2p0.CommitteeIndex(committeeIndex)].Len()
		// Iterate over all validators in the committee.
		for idx := range validatorsInCommittee {
			// Update the existing map if the said validator attested.
			if fullAttestationAggregationBits.BitAt(offset + idx) {
				committeeAggregation[eth2p0.CommitteeIndex(committeeIndex)].SetBitAt(idx, fullAttestationAggregationBits.BitAt(offset+idx))
			}
		}
		offset += validatorsInCommittee
	}

	return committeeAggregation
}
