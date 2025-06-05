// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tracker

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"sync"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/featureset"
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
	AttDuties              []*eth2v1.AttesterDuty
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

// inclusionCore tracks the inclusion of submitted duties.
// It has a simplified API to allow for easy testing.
type inclusionCore struct {
	mu              sync.Mutex
	submissions     map[subkey]submission
	stateCommittees map[eth2p0.Slot][]*statecomm.StateCommittee

	trackerInclFunc trackerInclFunc
	missedFunc      func(context.Context, submission)
	attIncludedFunc func(context.Context, submission, block)
}

// inclSupported defines duty types for which inclusion checks are supported.
func inclSupported() map[core.DutyType]bool {
	inclSupported := map[core.DutyType]bool{
		core.DutyProposer: true,
	}
	if featureset.Enabled(featureset.AttestationInclusion) {
		inclSupported[core.DutyAttester] = true
		inclSupported[core.DutyAggregator] = true
	}

	return inclSupported
}

// Submitted is called when a duty is submitted to the beacon node.
// It adds the duty to the list of submitted duties.
func (i *inclusionCore) Submitted(duty core.Duty, pubkey core.PubKey, data core.SignedData, delay time.Duration) (err error) {
	if !inclSupported()[duty.Type] {
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
	}

	if duty.Type == core.DutyAggregator {
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
	}

	if duty.Type == core.DutyProposer {
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

		//nolint: gocritic // Prefer clearer separation of blinded <-> unblinded.
		if block.Blinded {
			blinded, err := block.ToBlinded()
			if err != nil {
				return errors.Wrap(err, "expected blinded proposal")
			}

			if eth2wrap.IsSyntheticBlindedBlock(&blinded) {
				// Report inclusion for synthetic blocks as it is already included on-chain.
				i.trackerInclFunc(duty, pubkey, data, nil)

				return nil
			}
		} else {
			if eth2wrap.IsSyntheticProposal(&block.VersionedSignedProposal) {
				// Report inclusion for synthetic blocks as it is already included on-chain.
				i.trackerInclFunc(duty, pubkey, data, nil)

				return nil
			}
		}
	}

	if duty.Type == core.DutyBuilderProposer {
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
func (i *inclusionCore) CheckBlock(ctx context.Context, slot uint64, found bool) {
	i.mu.Lock()
	defer i.mu.Unlock()

	for key, sub := range i.submissions {
		switch sub.Duty.Type {
		case core.DutyProposer:
			if sub.Duty.Slot != slot {
				continue
			}

			proposal, ok := sub.Data.(core.VersionedSignedProposal)
			if !ok {
				log.Error(ctx, "Submission data has wrong type", nil, z.Str("type", fmt.Sprintf("%T", sub.Data)))
				continue
			}

			if found {
				var msg string
				msg = "Broadcasted block included on-chain"
				if proposal.Blinded {
					msg = "Broadcasted blinded block included on-chain"
				}
				log.Info(ctx, msg,
					z.U64("block_slot", slot),
					z.Any("pubkey", sub.Pubkey),
					z.Any("broadcast_delay", sub.Delay),
				)
			} else {
				i.missedFunc(ctx, sub)
			}

			// Just report block inclusions to tracker and trim
			i.trackerInclFunc(sub.Duty, sub.Pubkey, sub.Data, nil)
			delete(i.submissions, key)
		default:
			panic("bug: unexpected type") // Sanity check, this should never happen
		}
	}
}

// CheckBlockAndAtts checks whether the block includes any of the submitted duties.
func (i *inclusionCore) CheckBlockAndAtts(ctx context.Context, block block) {
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

	// Delete
	if block.Slot >= InclMissedLag {
		delete(i.stateCommittees, eth2p0.Slot(block.Slot-InclMissedLag))
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
	subData, ok := sub.Data.(core.VersionedAttestation)
	if !ok {
		return false, errors.New("not an attestation block data")
	}

	att, ok := block.AttestationsByDataRoot[sub.AttDataRoot]
	if !ok {
		return false, nil
	}

	switch subData.Version {
	case eth2spec.DataVersionPhase0, eth2spec.DataVersionAltair, eth2spec.DataVersionBellatrix, eth2spec.DataVersionCapella, eth2spec.DataVersionDeneb:
		subBits, err := subData.AggregationBits()
		if err != nil {
			return false, errors.Wrap(err, "fetch submission aggregation bits from phase0 attestation")
		}
		attAggBits, err := att.AggregationBits()
		if err != nil {
			return false, errors.Wrap(err, "fetch attestation aggregation bits from phase0 attestation")
		}
		ok, err := attAggBits.Contains(subBits)
		if err != nil {
			return false, errors.Wrap(err, "check phase0 aggregation bits",
				z.U64("block_bits", attAggBits.Len()),
				z.U64("sub_bits", subBits.Len()),
			)
		}

		return ok, nil
	case eth2spec.DataVersionElectra:
		if subData.ValidatorIndex == nil {
			return false, errors.New("no validator index in electra attestation")
		}

		var attesterDutyData *eth2v1.AttesterDuty
		for _, ad := range block.AttDuties {
			if *subData.ValidatorIndex == ad.ValidatorIndex {
				attesterDutyData = ad
				break
			}
		}

		if attesterDutyData == nil {
			return false, errors.New("no attester duty data found in electra attestation")
		}

		attAggBits, err := att.AggregationBits()
		if err != nil {
			return false, errors.Wrap(err, "get attestation aggregation bits from phase0 attestation")
		}

		subCommIdx, err := subData.CommitteeIndex()
		if err != nil {
			return false, errors.Wrap(err, "get committee index from phase0 attestation")
		}

		// Calculate the length of validators of committees before the committee index of the submitted attestation.
		previousCommsValidatorsLen := 0
		for idx := range subCommIdx {
			previousCommsValidatorsLen += len(block.BeaconCommitees[idx].Validators)
		}

		// Previous committees validators length + validator index in attestation committee gives the index of the attestation in the full agreggation bits bitlist.
		return attAggBits.BitAt(uint64(previousCommsValidatorsLen) + attesterDutyData.ValidatorCommitteeIndex), nil
	default:
		return false, errors.New("unknown version", z.Str("version", subData.Version.String()))
	}
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
	att, ok := block.AttestationsByDataRoot[sub.AttDataRoot]
	if !ok {
		return
	}
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
	)

	inclusionDelay.Set(float64(blockSlot - attSlot))
}

// NewInclusion returns a new InclusionChecker.
func NewInclusion(ctx context.Context, eth2Cl eth2wrap.Client, trackerInclFunc trackerInclFunc) (*InclusionChecker, error) {
	genesisTime, err := eth2wrap.FetchGenesisTime(ctx, eth2Cl)
	if err != nil {
		return nil, err
	}
	slotDuration, _, err := eth2wrap.FetchSlotsConfig(ctx, eth2Cl)
	if err != nil {
		return nil, errors.Wrap(err, "fetch slots config")
	}

	inclCore := &inclusionCore{
		attIncludedFunc: reportAttInclusion,
		missedFunc:      reportMissed,
		trackerInclFunc: trackerInclFunc,
		submissions:     make(map[subkey]submission),
		stateCommittees: make(map[eth2p0.Slot][]*statecomm.StateCommittee),
	}

	return &InclusionChecker{
		core:                  inclCore,
		eth2Cl:                eth2Cl,
		genesis:               genesisTime,
		slotDuration:          slotDuration,
		checkBlockFunc:        inclCore.CheckBlock,
		checkBlockAndAttsFunc: inclCore.CheckBlockAndAtts, // used when feature flag attestation_inclusion is enabled
	}, nil
}

// InclusionChecker checks whether duties have been included on-chain.
type InclusionChecker struct {
	genesis               time.Time
	slotDuration          time.Duration
	eth2Cl                eth2wrap.Client
	core                  *inclusionCore
	checkBlockFunc        func(ctx context.Context, slot uint64, found bool)
	checkBlockAndAttsFunc func(ctx context.Context, block block) // used when feature flag attestation_inclusion is enabled
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

	_, slotsPerEpoch, err := eth2wrap.FetchSlotsConfig(ctx, a.eth2Cl)
	if err != nil {
		log.Warn(ctx, "Failed to fetch eth2 spec and start inclusion checker", err)
		return
	}

	var checkedSlot uint64
	var attesterDuties []*eth2v1.AttesterDuty

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			slot := uint64(time.Since(a.genesis)/a.slotDuration) - InclCheckLag
			if checkedSlot == slot {
				continue
			}
			epoch := eth2p0.Epoch(slot) / eth2p0.Epoch(slotsPerEpoch)
			indices := []eth2p0.ValidatorIndex{}
			a.core.mu.Lock()
			subs := maps.Clone(a.core.submissions)
			a.core.mu.Unlock()
			for _, s := range subs {
				att, ok := s.Data.(core.VersionedAttestation)
				if !ok {
					continue
				}
				if att.ValidatorIndex == nil {
					continue
				}
				indices = append(indices, *att.ValidatorIndex)
			}

			// check if there are pending unchecked submissions are made
			if len(indices) == 0 {
				attesterDuties = []*eth2v1.AttesterDuty{}
			} else {
				// TODO: This can be optimised by not calling attester duties on every slot, in the case of small clusters, where there are <32 validators per cluster.
				opts := &eth2api.AttesterDutiesOpts{
					Epoch:   epoch,
					Indices: indices,
				}
				resp, err := a.eth2Cl.AttesterDuties(ctx, opts)
				if err != nil {
					log.Warn(ctx, "Failed to fetch attester duties for epoch", err, z.U64("epoch", uint64(epoch)), z.Any("indices", indices))
					attesterDuties = []*eth2v1.AttesterDuty{}
				} else {
					attesterDuties = resp.Data
				}
			}

			if err := a.checkBlock(ctx, slot, attesterDuties); err != nil {
				log.Warn(ctx, "Failed to check inclusion", err, z.U64("slot", slot))
				continue
			}

			checkedSlot = slot
			a.core.Trim(ctx, slot-InclMissedLag)
		}
	}
}

func (a *InclusionChecker) checkBlock(ctx context.Context, slot uint64, attDuties []*eth2v1.AttesterDuty) error {
	if featureset.Enabled(featureset.AttestationInclusion) {
		return a.checkBlockAndAtts(ctx, slot, attDuties)
	}

	block, err := a.eth2Cl.Block(ctx, strconv.FormatUint(slot, 10))
	if err != nil {
		return err
	}
	var found bool
	if block != nil {
		found = true
	} else {
		found = false
	}

	a.checkBlockFunc(ctx, slot, found)

	return nil
}

func (a *InclusionChecker) checkBlockAndAtts(ctx context.Context, slot uint64, attDuties []*eth2v1.AttesterDuty) error {
	atts, err := a.eth2Cl.BlockAttestations(ctx, strconv.FormatUint(slot, 10))
	if err != nil {
		return err
	} else if len(atts) == 0 {
		return nil // No block for this slot
	}

	var committeesForState []*statecomm.StateCommittee
	var checkedSlots []eth2p0.Slot
	for _, att := range atts {
		attestationData, err := att.Data()
		if err != nil {
			return err
		}

		// State committess for the said slot were already fetched.
		if slices.Contains(checkedSlots, attestationData.Slot) {
			continue
		}

		stateComms, ok := a.core.stateCommittees[attestationData.Slot]
		if ok {
			committeesForState = append(committeesForState, stateComms...)
		} else {
			// Get the beacon committee for the above mentioned slot.
			fetchedCommitteesForState, err := a.eth2Cl.BeaconStateCommittees(ctx, uint64(attestationData.Slot))
			if err != nil {
				return err
			}
			committeesForState = append(committeesForState, fetchedCommitteesForState...)
			a.core.stateCommittees[attestationData.Slot] = fetchedCommitteesForState
		}
		checkedSlots = append(checkedSlots, attestationData.Slot)
	}

	if len(committeesForState) == 0 {
		return nil // no committees
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

	a.checkBlockAndAttsFunc(ctx, block{Slot: slot, AttDuties: attDuties, AttestationsByDataRoot: attsMap, BeaconCommitees: committeesForState})

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
		commIdx := eth2p0.CommitteeIndex(committeeIndex)
		validatorsInCommittee := committeeAggregation[commIdx].Len()
		// Iterate over all validators in the committee.
		for idx := range validatorsInCommittee {
			// Update the existing map if the said validator attested.
			if fullAttestationAggregationBits.BitAt(offset + idx) {
				committeeAggregation[commIdx].SetBitAt(idx, true)
			}
		}
		offset += validatorsInCommittee
	}

	return committeeAggregation
}
