// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatormock

import (
	"context"
	"sync"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/electra"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/eth2util/signing"
)

// Type aliases for concise function signatures.
type (
	attDuties     []*eth2v1.AttesterDuty
	attSelections []*eth2exp.BeaconCommitteeSelection
	attDatas      []*eth2p0.AttestationData
)

// NewSlotAttester returns a new SlotAttester.
func NewSlotAttester(eth2Cl eth2wrap.Client, slot eth2p0.Slot, signFunc SignFunc, pubkeys []eth2p0.BLSPubKey) *SlotAttester {
	return &SlotAttester{
		eth2Cl:       eth2Cl,
		slot:         slot,
		pubkeys:      pubkeys,
		signFunc:     signFunc,
		dutiesOK:     make(chan struct{}),
		selectionsOK: make(chan struct{}),
		datasOK:      make(chan struct{}),
	}
}

// SlotAttester is a stateful structure providing a slot attestation and aggregation API excluding scheduling.
type SlotAttester struct {
	// Immutable fields
	eth2Cl   eth2wrap.Client
	slot     eth2p0.Slot
	pubkeys  []eth2p0.BLSPubKey
	signFunc SignFunc

	// Mutable fields
	mutable struct {
		sync.Mutex

		vals       eth2wrap.ActiveValidators
		duties     attDuties
		selections attSelections
		datas      attDatas
	}

	dutiesOK     chan struct{}
	selectionsOK chan struct{}
	datasOK      chan struct{}
}

// Slot returns the attester slot.
func (a *SlotAttester) Slot() eth2p0.Slot {
	return a.slot
}

// Prepare should be called at the start of slot, it does the following:
// - Filters active validators for the slot (this could be cached at start of epoch)
// - Fetches attester attDuties for the slot (this could be cached at start of epoch).
// - Prepares aggregation attDuties for slot attesters.
// It panics if called more than once.
func (a *SlotAttester) Prepare(ctx context.Context) error {
	vals, err := a.eth2Cl.ActiveValidators(ctx)
	if err != nil {
		return err
	}

	duties, err := prepareAttesters(ctx, a.eth2Cl, vals, a.slot)
	if err != nil {
		return err
	}

	a.setPrepareDuties(vals, duties)

	log.Debug(ctx, "Set attester duties", z.Any("slot", a.slot))

	selections, err := prepareAggregators(ctx, a.eth2Cl, a.signFunc, vals, duties, a.slot)
	if err != nil {
		return err
	}

	a.setPrepareSelections(selections)

	return nil
}

// Attest should be called at latest 1/3 into the slot, it does slot attestations.
func (a *SlotAttester) Attest(ctx context.Context) error {
	// Wait for Prepare complete
	wait(ctx, a.dutiesOK)

	datas, err := attest(ctx, a.eth2Cl, a.signFunc, a.slot, a.getAttDuties())
	if err != nil {
		return err
	}

	a.setAttestDatas(datas)

	return nil
}

// Aggregate should be called at latest 2/3 into the slot, it does slot attestation aggregations.
func (a *SlotAttester) Aggregate(ctx context.Context) (bool, error) {
	// Wait for Prepare and Attest to complete
	wait(ctx, a.dutiesOK, a.selectionsOK, a.datasOK)

	return aggregate(ctx, a.eth2Cl, a.signFunc, a.slot, a.getVals(),
		a.getAttDuties(), a.getSelections(), a.getDatas())
}

func (a *SlotAttester) setPrepareDuties(vals eth2wrap.ActiveValidators, duties attDuties) {
	a.mutable.Lock()
	defer a.mutable.Unlock()

	a.mutable.vals = vals
	a.mutable.duties = duties
	close(a.dutiesOK)
}

func (a *SlotAttester) setPrepareSelections(selections attSelections) {
	a.mutable.Lock()
	defer a.mutable.Unlock()

	a.mutable.selections = selections
	close(a.selectionsOK)
}

func (a *SlotAttester) setAttestDatas(datas attDatas) {
	a.mutable.Lock()
	defer a.mutable.Unlock()

	a.mutable.datas = datas
	close(a.datasOK)
}

func (a *SlotAttester) getVals() eth2wrap.ActiveValidators {
	a.mutable.Lock()
	defer a.mutable.Unlock()

	return a.mutable.vals
}

func (a *SlotAttester) getAttDuties() attDuties {
	a.mutable.Lock()
	defer a.mutable.Unlock()

	return a.mutable.duties
}

func (a *SlotAttester) getSelections() attSelections {
	a.mutable.Lock()
	defer a.mutable.Unlock()

	return a.mutable.selections
}

func (a *SlotAttester) getDatas() attDatas {
	a.mutable.Lock()
	defer a.mutable.Unlock()

	return a.mutable.datas
}

// wait returns when either all the channels or the context is closed.
func wait(ctx context.Context, chs ...chan struct{}) {
	for _, ch := range chs {
		select {
		case <-ctx.Done():
		case <-ch:
		}
	}
}

// prepareAttesters returns the attesters (including duty and data) for the provided validators and slot.
func prepareAttesters(ctx context.Context, eth2Cl eth2wrap.Client, vals eth2wrap.ActiveValidators,
	slot eth2p0.Slot,
) (attDuties, error) {
	if len(vals) == 0 {
		return nil, nil
	}

	epoch, err := eth2util.EpochFromSlot(ctx, eth2Cl, slot)
	if err != nil {
		return nil, err
	}

	opts := &eth2api.AttesterDutiesOpts{
		Epoch:   epoch,
		Indices: vals.Indices(),
	}

	eth2Resp, err := eth2Cl.AttesterDuties(ctx, opts)
	if err != nil {
		return nil, err
	}

	epochDuties := eth2Resp.Data

	var duties attDuties

	for _, duty := range epochDuties {
		if duty.Slot != slot {
			continue
		}

		duties = append(duties, duty)
	}

	return duties, nil
}

// prepareAggregators does beacon committee subscription selection for the provided attesters
// and returns the selected aggregators.
func prepareAggregators(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc,
	vals eth2wrap.ActiveValidators, duties attDuties, slot eth2p0.Slot,
) (attSelections, error) {
	if len(duties) == 0 {
		return nil, nil
	}

	epoch, err := eth2util.EpochFromSlot(ctx, eth2Cl, slot)
	if err != nil {
		return nil, err
	}

	slotRoot, err := eth2util.SlotHashRoot(slot)
	if err != nil {
		return nil, err
	}

	sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainSelectionProof, epoch, slotRoot)
	if err != nil {
		return nil, err
	}

	var (
		partials    []*eth2exp.BeaconCommitteeSelection
		commLengths = make(map[eth2p0.ValidatorIndex]uint64)
	)
	for _, duty := range duties {
		pubkey, ok := vals[duty.ValidatorIndex]
		if !ok {
			return nil, errors.New("missing validator index")
		}

		slotSig, err := signFunc(pubkey, sigData[:])
		if err != nil {
			return nil, err
		}

		commLengths[duty.ValidatorIndex] = duty.CommitteeLength

		partials = append(partials, &eth2exp.BeaconCommitteeSelection{
			ValidatorIndex: duty.ValidatorIndex,
			Slot:           duty.Slot,
			SelectionProof: slotSig,
		})
	}

	aggregateSelections, err := eth2Cl.AggregateBeaconCommitteeSelections(ctx, partials)
	if err != nil {
		return nil, err
	}

	var selections attSelections

	for _, selection := range aggregateSelections {
		ok, err := eth2exp.IsAttAggregator(ctx, eth2Cl, commLengths[selection.ValidatorIndex], selection.SelectionProof)
		if err != nil {
			return nil, err
		} else if !ok {
			continue
		}

		selections = append(selections, selection)
	}

	log.Info(ctx, "Mock beacon committee subscription submitted", z.Int("aggregators", len(selections)))

	return selections, nil
}

// attest does attestations for the provided attesters and returns the attestation attDatas.
func attest(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc, slot eth2p0.Slot, duties attDuties,
) (attDatas, error) {
	if len(duties) == 0 {
		return nil, nil
	}

	// Group attDuties by committee.
	dutyByComm := make(map[eth2p0.CommitteeIndex][]*eth2v1.AttesterDuty)
	for _, duty := range duties {
		dutyByComm[duty.CommitteeIndex] = append(dutyByComm[duty.CommitteeIndex], duty)
	}

	var (
		atts  []*eth2spec.VersionedAttestation
		datas attDatas
	)

	for commIdx, duties := range dutyByComm {
		opts := &eth2api.AttestationDataOpts{
			Slot:           slot,
			CommitteeIndex: commIdx,
		}

		eth2Resp, err := eth2Cl.AttestationData(ctx, opts)
		if err != nil {
			return nil, err
		}

		data := eth2Resp.Data
		datas = append(datas, data)

		root, err := data.HashTreeRoot()
		if err != nil {
			return nil, errors.Wrap(err, "hash attestation")
		}

		sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainBeaconAttester, data.Target.Epoch, root)
		if err != nil {
			return nil, err
		}

		for _, duty := range duties {
			sig, err := signFunc(duty.PubKey, sigData[:])
			if err != nil {
				return nil, err
			}

			aggBits := bitfield.NewBitlist(duty.CommitteeLength)
			aggBits.SetBitAt(duty.ValidatorCommitteeIndex, true)

			commBits := bitfield.NewBitvector64()
			commBits.SetBitAt(uint64(duty.CommitteeIndex), true)

			atts = append(atts, &eth2spec.VersionedAttestation{
				Version:        eth2spec.DataVersionElectra,
				ValidatorIndex: &duty.ValidatorIndex,
				Electra: &electra.Attestation{
					AggregationBits: aggBits,
					Data:            data,
					Signature:       sig,
					CommitteeBits:   commBits,
				},
			})
		}
	}

	err := eth2Cl.SubmitAttestations(ctx, &eth2api.SubmitAttestationsOpts{Attestations: atts})
	if err != nil {
		return nil, err
	}

	return datas, nil
}

// aggregate does attestation aggregation for the provided validators, attSelections and attestation attDatas and returns true.
// It returns false if aggregation is not required.
func aggregate(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc, slot eth2p0.Slot,
	vals eth2wrap.ActiveValidators, duties attDuties, selections attSelections, datas attDatas,
) (bool, error) {
	if len(selections) == 0 {
		return false, nil
	}

	epoch, err := eth2util.EpochFromSlot(ctx, eth2Cl, slot)
	if err != nil {
		return false, err
	}

	committees := make(map[eth2p0.ValidatorIndex]eth2p0.CommitteeIndex)
	for _, duty := range duties {
		committees[duty.ValidatorIndex] = duty.CommitteeIndex
	}

	var (
		aggs       []*eth2spec.VersionedSignedAggregateAndProof
		attsByComm = make(map[eth2p0.CommitteeIndex]*eth2spec.VersionedAttestation)
	)

	for _, selection := range selections {
		commIdx, ok := committees[selection.ValidatorIndex]
		if !ok {
			return false, errors.New("missing duty for selection")
		}

		att, ok := attsByComm[commIdx]
		if !ok {
			var err error

			att, err = getAggregateAttestation(ctx, eth2Cl, datas, commIdx)
			if err != nil {
				return false, err
			}

			attsByComm[commIdx] = att
		}

		proof := eth2spec.VersionedAggregateAndProof{
			Version: eth2spec.DataVersionElectra,
			Electra: &electra.AggregateAndProof{
				AggregatorIndex: selection.ValidatorIndex,
				Aggregate:       att.Electra,
				SelectionProof:  selection.SelectionProof,
			},
		}

		proofRoot, err := proof.HashTreeRoot()
		if err != nil {
			return false, err
		}

		sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainAggregateAndProof, epoch, proofRoot)
		if err != nil {
			return false, err
		}

		pubkey, ok := vals[selection.ValidatorIndex]
		if !ok {
			return false, errors.New("missing validator index", z.U64("vidx", uint64(selection.ValidatorIndex)))
		}

		proofSig, err := signFunc(pubkey, sigData[:])
		if err != nil {
			return false, err
		}

		aggs = append(aggs, &eth2spec.VersionedSignedAggregateAndProof{
			Version: eth2spec.DataVersionElectra,
			Electra: &electra.SignedAggregateAndProof{
				Message:   proof.Electra,
				Signature: proofSig,
			},
		})
	}

	if err := eth2Cl.SubmitAggregateAttestations(ctx, &eth2api.SubmitAggregateAttestationsOpts{SignedAggregateAndProofs: aggs}); err != nil {
		return false, err
	}

	return true, nil
}

// getAggregateAttestation returns an aggregated attestation for the provided committee.
func getAggregateAttestation(ctx context.Context, eth2Cl eth2wrap.Client, datas attDatas,
	commIdx eth2p0.CommitteeIndex,
) (*eth2spec.VersionedAttestation, error) {
	for _, data := range datas {
		if data.Index != commIdx {
			continue
		}

		root, err := data.HashTreeRoot()
		if err != nil {
			return nil, errors.Wrap(err, "hash attestation data")
		}

		opts := &eth2api.AggregateAttestationOpts{
			Slot:                data.Slot,
			AttestationDataRoot: root,
			CommitteeIndex:      commIdx,
		}

		eth2Resp, err := eth2Cl.AggregateAttestation(ctx, opts)
		if err != nil {
			return nil, err
		}

		return eth2Resp.Data, nil
	}

	return nil, errors.New("missing attestation data for committee index")
}
