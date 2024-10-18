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
	AttestationsByDataRoot map[eth2p0.Root]*eth2spec.VersionedAttestation
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

	trackerInclFunc trackerInclFunc
	missedFunc      func(context.Context, submission)
	attIncludedFunc func(context.Context, submission, block)
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
		if !ok {
			return errors.New("invalid attestation")
		}
		attData, err := att.Data()
		if err != nil {
			return errors.Wrap(err, "get attestation data")
		}
		attRoot, err = attData.HashTreeRoot()
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

// checkAggregationInclusion checks whether the aggregation is included in the block.
func checkAggregationInclusion(sub submission, block block) (bool, error) {
	att, ok := block.AttestationsByDataRoot[sub.AttDataRoot]
	if !ok {
		return false, nil
	}

	attAggregationBits, err := att.AggregationBits()
	if err != nil {
		return false, errors.Wrap(err, "get attestation aggregation bits")
	}
	subBits := sub.Data.(core.SignedAggregateAndProof).Message.Aggregate.AggregationBits
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

	attAggregationBits, err := att.AggregationBits()
	if err != nil {
		return false, errors.Wrap(err, "get attestation aggregation bits")
	}
	subBits, err := sub.Data.(core.VersionedAttestation).AggregationBits()
	if err != nil {
		return false, errors.Wrap(err, "get attestation aggregation bits")
	}
	ok, err = attAggregationBits.Contains(subBits)
	if err != nil {
		return false, errors.Wrap(err, "check aggregation bits",
			z.U64("block_bits", attAggregationBits.Len()),
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

// reportAttInclusion reports attestations that were included in a block.
func reportAttInclusion(ctx context.Context, sub submission, block block) {
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
	atts, err := a.eth2Cl.BlockAttestations(ctx, strconv.FormatUint(slot, 10))
	if err != nil {
		return err
	} else if len(atts) == 0 {
		return nil // No block for this slot
	}

	// Map attestations by data root, merging duplicates (with identical attestation data).
	attsMap := make(map[eth2p0.Root]*eth2spec.VersionedAttestation)
	for _, att := range atts {
		if att == nil {
			return errors.New("invalid attestation")
		}

		attData, err := att.Data()
		if err != nil {
			return errors.New("invalid attestation")
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

		attAggregationBits, err := att.AggregationBits()
		if err != nil {
			return errors.Wrap(err, "get attestation aggregation bits")
		}

		if exist, ok := attsMap[root]; ok {
			existAttAggregationBits, err := exist.AggregationBits()
			if err != nil {
				return errors.Wrap(err, "get attestation aggregation bits")
			}
			// Merge duplicate attestations (only aggregation bits)
			bits, err := attAggregationBits.Or(existAttAggregationBits)
			if err != nil {
				return errors.Wrap(err, "merge attestation aggregation bits")
			}
			err = setAttestationAggregationBits(*att, bits)
			if err != nil {
				return errors.Wrap(err, "set attestation aggregation bits")
			}
		}

		attsMap[root] = att
	}

	a.checkBlockFunc(ctx, block{Slot: slot, AttestationsByDataRoot: attsMap})

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
