// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package validatormock

import (
	"context"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/eth2util/signing"
)

// Type aliases for concise function signatures.
type (
	validators map[eth2p0.ValidatorIndex]*eth2v1.Validator
	duties     []*eth2v1.AttesterDuty
	selections []*eth2exp.BeaconCommitteeSubscriptionResponse
	datas      []*eth2p0.AttestationData
)

// NewSlotAttester returns a new SlotAttester.
func NewSlotAttester(eth2Cl eth2wrap.Client, slot eth2p0.Slot, signFunc SignFunc, pubkeys []eth2p0.BLSPubKey) *SlotAttester {
	return &SlotAttester{
		eth2Cl:      eth2Cl,
		slot:        slot,
		pubkeys:     pubkeys,
		signFunc:    signFunc,
		dutiesOK:    make(chan struct{}),
		selectinsOK: make(chan struct{}),
		datasOK:     make(chan struct{}),
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
	vals        validators
	duties      duties
	selections  selections
	datas       datas
	dutiesOK    chan struct{}
	selectinsOK chan struct{}
	datasOK     chan struct{}
}

// Slot returns the attester slot.
func (a *SlotAttester) Slot() eth2p0.Slot {
	return a.slot
}

// Prepare should be called at the start of slot, it does the following:
// - Filters active validators for the slot (this could be cached at start of epoch)
// - Fetches attester duties for the slot (this could be cached at start of epoch).
// - Prepares aggregation duties for slot attesters.
// It panics if called more than once.
func (a *SlotAttester) Prepare(ctx context.Context) error {
	var err error

	a.vals, err = activeValidators(ctx, a.eth2Cl, a.pubkeys)
	if err != nil {
		return err
	}

	a.duties, err = prepareAttesters(ctx, a.eth2Cl, a.vals, a.slot)
	if err != nil {
		return err
	}
	close(a.dutiesOK)

	a.selections, err = prepareAggregators(ctx, a.eth2Cl, a.signFunc, a.vals, a.duties, a.slot)
	if err != nil {
		return err
	}
	close(a.selectinsOK)

	return nil
}

// Attest should be called at latest 1/3 into the slot, it does slot attestations.
func (a *SlotAttester) Attest(ctx context.Context) error {
	// Wait for Prepare complete
	<-a.dutiesOK

	var err error
	a.datas, err = attest(ctx, a.eth2Cl, a.signFunc, a.slot, a.duties)
	if err != nil {
		return err
	}
	close(a.datasOK)

	return nil
}

// Aggregate should be called at latest 2/3 into the slot, it does slot attestation aggregations.
func (a *SlotAttester) Aggregate(ctx context.Context) error {
	s := a.slot
	// Wait for Prepare and Attest to complete
	<-a.selectinsOK
	<-a.datasOK

	if a.slot != s {
		panic("what!")
	}
	return aggregate(ctx, a.eth2Cl, a.signFunc, a.slot, a.vals, a.selections, a.datas)
}

// activeValidators returns the head active validators for the public keys.
func activeValidators(ctx context.Context, eth2Cl eth2wrap.Client,
	pubkeys []eth2p0.BLSPubKey,
) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
	// Using head to mitigate future slot issues.
	vals, err := eth2Cl.ValidatorsByPubKey(ctx, "head", pubkeys)
	if err != nil {
		return nil, err
	}

	resp := make(map[eth2p0.ValidatorIndex]*eth2v1.Validator)
	for idx, val := range vals {
		if !val.Status.IsActive() {
			continue
		}
		resp[idx] = val
	}

	return resp, nil
}

// prepareAttesters returns the attesters (including duty and data) for the provided validators and slot.
func prepareAttesters(ctx context.Context, eth2Cl eth2wrap.Client, vals validators,
	slot eth2p0.Slot,
) (duties, error) {
	if len(vals) == 0 {
		return nil, nil
	}

	epoch, err := epochFromSlot(ctx, eth2Cl, slot)
	if err != nil {
		return nil, err
	}

	var indexes []eth2p0.ValidatorIndex
	for idx := range vals {
		indexes = append(indexes, idx)
	}

	epochDuties, err := eth2Cl.AttesterDuties(ctx, epoch, indexes)
	if err != nil {
		return nil, err
	}

	var duties duties
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
	vals validators, duties duties, slot eth2p0.Slot,
) (selections, error) {
	if len(duties) == 0 {
		return nil, nil
	}

	epoch, err := epochFromSlot(ctx, eth2Cl, slot)
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

	var subs []*eth2exp.BeaconCommitteeSubscription
	for _, duty := range duties {
		val, ok := vals[duty.ValidatorIndex]
		if !ok {
			return nil, errors.New("missing validator index")
		}

		slotSig, err := signFunc(val.Validator.PublicKey, sigData[:])
		if err != nil {
			return nil, err
		}

		subs = append(subs, &eth2exp.BeaconCommitteeSubscription{
			ValidatorIndex:   duty.ValidatorIndex,
			Slot:             duty.Slot,
			CommitteeIndex:   duty.CommitteeIndex,
			CommitteesAtSlot: duty.CommitteesAtSlot,
			SlotSignature:    slotSig,
		})
	}

	allSelections, err := eth2Cl.SubmitBeaconCommitteeSubscriptionsV2(ctx, subs)
	if err != nil {
		return nil, err
	}

	var selections selections
	for _, selection := range allSelections {
		if !selection.IsAggregator {
			continue
		}
		selections = append(selections, selection)
	}

	return selections, nil
}

// attest does attestations for the provided attesters and returns the attestation datas.
func attest(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc, slot eth2p0.Slot, duties duties,
) (datas, error) {
	if len(duties) == 0 {
		return nil, nil
	}

	// Group duties by committee.
	dutyByComm := make(map[eth2p0.CommitteeIndex][]*eth2v1.AttesterDuty)
	for _, duty := range duties {
		dutyByComm[duty.CommitteeIndex] = append(dutyByComm[duty.CommitteeIndex], duty)
	}

	var (
		atts  []*eth2p0.Attestation
		datas datas
	)
	for commIdx, duties := range dutyByComm {
		data, err := eth2Cl.AttestationData(ctx, slot, commIdx)
		if err != nil {
			return nil, err
		}
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

			atts = append(atts, &eth2p0.Attestation{
				AggregationBits: aggBits,
				Data:            data,
				Signature:       sig,
			})
		}
	}

	err := eth2Cl.SubmitAttestations(ctx, atts)
	if err != nil {
		return nil, err
	}

	return datas, nil
}

// aggregate does attestation aggregation for the provided validators, selections and attestation datas.
func aggregate(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc, slot eth2p0.Slot,
	vals validators, selections selections, datas datas,
) error {
	if len(selections) == 0 {
		return nil
	}

	epoch, err := epochFromSlot(ctx, eth2Cl, slot)
	if err != nil {
		return err
	}

	var (
		aggs       []*eth2p0.SignedAggregateAndProof
		attsByComm = make(map[eth2p0.CommitteeIndex]*eth2p0.Attestation)
	)
	for _, selection := range selections {
		if !selection.IsAggregator {
			continue
		}

		commIdx := selection.CommitteeIndex

		att, ok := attsByComm[commIdx]
		if !ok {
			var err error
			att, err = getAggregateAttestation(ctx, eth2Cl, datas, commIdx)
			if err != nil {
				return err
			}
			attsByComm[commIdx] = att
		}

		// TODO(corver): Should we ensure our own attestation is included?

		proof := eth2p0.AggregateAndProof{
			AggregatorIndex: selection.ValidatorIndex,
			Aggregate:       att,
			SelectionProof:  selection.SelectionProof,
		}

		proofRoot, err := proof.HashTreeRoot()
		if err != nil {
			return err
		}

		sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainAggregateAndProof, epoch, proofRoot)
		if err != nil {
			return err
		}

		val, ok := vals[selection.ValidatorIndex]
		if !ok {
			return errors.New("missing validator index")
		}

		proofSig, err := signFunc(val.Validator.PublicKey, sigData[:])
		if err != nil {
			return err
		}

		aggs = append(aggs, &eth2p0.SignedAggregateAndProof{
			Message:   &proof,
			Signature: proofSig,
		})
	}

	return eth2Cl.SubmitAggregateAttestations(ctx, aggs)
}

// getAggregateAttestation returns an aggregated attestation for the provided committee.
func getAggregateAttestation(ctx context.Context, eth2Cl eth2wrap.Client, datas datas,
	commIdx eth2p0.CommitteeIndex,
) (*eth2p0.Attestation, error) {
	for _, data := range datas {
		if data.Index != commIdx {
			continue
		}

		root, err := data.HashTreeRoot()
		if err != nil {
			return nil, errors.Wrap(err, "hash attestation data")
		}

		return eth2Cl.AggregateAttestation(ctx, data.Slot, root)
	}

	return nil, errors.New("missing attestation data for committee index")
}

// epochFromSlot returns the epoch of the provided slot.
func epochFromSlot(ctx context.Context, eth2Cl eth2wrap.Client, slot eth2p0.Slot) (eth2p0.Epoch, error) {
	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return 0, err
	}

	return eth2p0.Epoch(uint64(slot) / slotsPerEpoch), nil
}
