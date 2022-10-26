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

package fetcher

import (
	"context"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
)

// New returns a new fetcher instance.
func New(eth2Cl eth2wrap.Client, feeRecipientAddress string) (*Fetcher, error) {
	return &Fetcher{
		eth2Cl:              eth2Cl,
		feeRecipientAddress: feeRecipientAddress,
	}, nil
}

// Fetcher fetches proposed duty data.
type Fetcher struct {
	eth2Cl              eth2wrap.Client
	feeRecipientAddress string
	subs                []func(context.Context, core.Duty, core.UnsignedDataSet) error
	aggSigDBFunc        func(context.Context, core.Duty, core.PubKey) (core.SignedData, error)
	awaitAttDataFunc    func(ctx context.Context, slot int64, commIdx int64) (*eth2p0.AttestationData, error)
}

// Subscribe registers a callback for fetched duties.
// Note this is not thread safe should be called *before* Fetch.
func (f *Fetcher) Subscribe(fn func(context.Context, core.Duty, core.UnsignedDataSet) error) {
	f.subs = append(f.subs, fn)
}

// Fetch triggers fetching of a proposed duty data set.
func (f *Fetcher) Fetch(ctx context.Context, duty core.Duty, defSet core.DutyDefinitionSet) error {
	var (
		unsignedSet core.UnsignedDataSet
		err         error
	)

	switch duty.Type {
	case core.DutyProposer:
		unsignedSet, err = f.fetchProposerData(ctx, duty.Slot, defSet)
		if err != nil {
			return errors.Wrap(err, "fetch proposer data")
		}
	case core.DutyAttester:
		unsignedSet, err = f.fetchAttesterData(ctx, duty.Slot, defSet)
		if err != nil {
			return errors.Wrap(err, "fetch attester data")
		}
	case core.DutyBuilderProposer:
		unsignedSet, err = f.fetchBuilderProposerData(ctx, duty.Slot, defSet)
		if err != nil {
			return errors.Wrap(err, "fetch proposer data")
		}
	case core.DutyAggregator:
		unsignedSet, err = f.fetchAggregatorData(ctx, duty.Slot, defSet)
		if err != nil {
			return errors.Wrap(err, "fetch aggregator data")
		} else if len(unsignedSet) == 0 { // No aggregators found in this slot
			return nil
		}
	default:
		return errors.New("unsupported duty type", z.Str("type", duty.Type.String()))
	}

	for _, sub := range f.subs {
		clone, err := unsignedSet.Clone() // Clone before calling each subscriber.
		if err != nil {
			return err
		}

		if err := sub(ctx, duty, clone); err != nil {
			return err
		}
	}

	return nil
}

// RegisterAggSigDB registers a function to get resolved aggregated signed data from AggSigDB.
// Note: This is not thread safe and should only be called *before* Fetch.
func (f *Fetcher) RegisterAggSigDB(fn func(context.Context, core.Duty, core.PubKey) (core.SignedData, error)) {
	f.aggSigDBFunc = fn
}

// RegisterAwaitAttData registers a function to get attestation data from DutyDB.
// Note: This is not thread safe and should only be called *before* Fetch.
func (f *Fetcher) RegisterAwaitAttData(fn func(ctx context.Context, slot int64, commIdx int64) (*eth2p0.AttestationData, error)) {
	f.awaitAttDataFunc = fn
}

// fetchAttesterData returns the fetched attestation data set for committees and validators in the arg set.
func (f *Fetcher) fetchAttesterData(ctx context.Context, slot int64, defSet core.DutyDefinitionSet,
) (core.UnsignedDataSet, error) {
	// We may have multiple validators in the same committee, use the same attestation data in that case.
	dataByCommIdx := make(map[eth2p0.CommitteeIndex]*eth2p0.AttestationData)

	attDataRoots := make(map[eth2p0.Root]bool)
	resp := make(core.UnsignedDataSet)
	for pubkey, def := range defSet {
		attDuty, ok := def.(core.AttesterDefinition)
		if !ok {
			return nil, errors.New("invalid attester definition")
		}

		commIdx := attDuty.CommitteeIndex

		eth2AttData, ok := dataByCommIdx[commIdx]
		if !ok {
			var err error
			eth2AttData, err = f.eth2Cl.AttestationData(ctx, eth2p0.Slot(uint64(slot)), commIdx)
			if err != nil {
				return nil, err
			}

			dataByCommIdx[commIdx] = eth2AttData
		}

		attData := core.AttestationData{
			Data: *eth2AttData,
			Duty: attDuty.AttesterDuty,
		}

		resp[pubkey] = attData

		// Store Attestation data root excluding committee index.
		clone, err := attData.Clone()
		if err != nil {
			return nil, err
		}

		data := clone.(core.AttestationData)
		data.Data.Index = 0
		root, err := data.Data.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		attDataRoots[root] = true
	}

	if len(attDataRoots) > 1 {
		// Increase inconsistent data counter when different attestation data are found for the same slot.
		inconsistentAttDataCounter.Inc()
	}

	return resp, nil
}

func (f *Fetcher) fetchAggregatorData(ctx context.Context, slot int64, defSet core.DutyDefinitionSet) (core.UnsignedDataSet, error) {
	resp := make(core.UnsignedDataSet)
	for pubkey, dutyDef := range defSet {
		attDef, ok := dutyDef.(core.AttesterDefinition)
		if !ok {
			return core.UnsignedDataSet{}, errors.New("invalid attester definition")
		}

		// Query AggSigDB for DutyPrepareAggregator to get beacon committee selections.
		prepAggData, err := f.aggSigDBFunc(ctx, core.NewPrepareAggregatorDuty(slot), pubkey)
		if err != nil {
			return core.UnsignedDataSet{}, err
		}

		selection, ok := prepAggData.(core.BeaconCommitteeSelection)
		if !ok {
			return core.UnsignedDataSet{}, errors.New("invalid beacon committee subscription")
		}

		ok, err = eth2exp.IsAggregator(ctx, f.eth2Cl, attDef.CommitteeLength, selection.SelectionProof)
		if err != nil {
			return core.UnsignedDataSet{}, err
		} else if !ok {
			log.Debug(ctx, "Attester not selected for aggregation duty", z.Any("pubkey", pubkey))
			continue
		}
		log.Info(ctx, "Resolved attester aggregation duty", z.Any("pubkey", pubkey))

		// Query DutyDB for Attestation data to get attestation data root.
		attData, err := f.awaitAttDataFunc(ctx, slot, int64(attDef.CommitteeIndex))
		if err != nil {
			return core.UnsignedDataSet{}, err
		}

		dataRoot, err := attData.HashTreeRoot()
		if err != nil {
			return core.UnsignedDataSet{}, err
		}

		// Query BN for aggregate attestation.
		aggAtt, err := f.eth2Cl.AggregateAttestation(ctx, eth2p0.Slot(slot), dataRoot)
		if err != nil {
			return core.UnsignedDataSet{}, err
		} else if aggAtt == nil {
			// Some beacon nodes return nil if the root is not found, return retryable error.
			// This could happen if the beacon node didn't subscribe to the correct subnet.
			return core.UnsignedDataSet{}, errors.New("aggregate attestation not found by root (retryable)", z.Hex("root", dataRoot[:]))
		}

		resp[pubkey] = core.AggregatedAttestation{
			Attestation: *aggAtt,
		}
	}

	return resp, nil
}

func (f *Fetcher) fetchProposerData(ctx context.Context, slot int64, defSet core.DutyDefinitionSet) (core.UnsignedDataSet, error) {
	resp := make(core.UnsignedDataSet)
	for pubkey := range defSet {
		// Fetch previously aggregated randao reveal from AggSigDB
		dutyRandao := core.NewRandaoDuty(slot)
		randaoData, err := f.aggSigDBFunc(ctx, dutyRandao, pubkey)
		if err != nil {
			return nil, err
		}

		randao := randaoData.Signature().ToETH2()

		// TODO(dhruv): replace hardcoded graffiti with the one from cluster-lock.json
		var graffiti [32]byte
		commitSHA, _ := version.GitCommit()
		copy(graffiti[:], fmt.Sprintf("charon/%s-%s", version.Version, commitSHA))
		block, err := f.eth2Cl.BeaconBlockProposal(ctx, eth2p0.Slot(uint64(slot)), randao, graffiti[:])
		if err != nil {
			return nil, err
		}

		// Ensure fee recipient is correctly populated in block.
		if block.Version == spec.DataVersionBellatrix {
			actual := fmt.Sprintf("%#x", block.Bellatrix.Body.ExecutionPayload.FeeRecipient)
			if actual != f.feeRecipientAddress {
				log.Warn(ctx, "Proposing block with unexpected fee recipient address", nil,
					z.Str("expected", f.feeRecipientAddress), z.Str("actual", actual))
			}
		}

		coreBlock, err := core.NewVersionedBeaconBlock(block)
		if err != nil {
			return nil, errors.Wrap(err, "new block")
		}

		resp[pubkey] = coreBlock
	}

	return resp, nil
}

func (f *Fetcher) fetchBuilderProposerData(ctx context.Context, slot int64, defSet core.DutyDefinitionSet) (core.UnsignedDataSet, error) {
	resp := make(core.UnsignedDataSet)
	for pubkey := range defSet {
		// Fetch previously aggregated randao reveal from AggSigDB
		dutyRandao := core.Duty{
			Slot: slot,
			Type: core.DutyRandao,
		}
		randaoData, err := f.aggSigDBFunc(ctx, dutyRandao, pubkey)
		if err != nil {
			return nil, err
		}

		randao := randaoData.Signature().ToETH2()

		// TODO(dhruv): replace hardcoded graffiti with the one from cluster-lock.json
		var graffiti [32]byte
		commitSHA, _ := version.GitCommit()
		copy(graffiti[:], fmt.Sprintf("charon/%s-%s", version.Version, commitSHA))
		block, err := f.eth2Cl.BlindedBeaconBlockProposal(ctx, eth2p0.Slot(uint64(slot)), randao, graffiti[:])
		if err != nil {
			return nil, err
		}

		// Ensure fee recipient is correctly populated in block.
		if block.Version == spec.DataVersionBellatrix {
			actual := fmt.Sprintf("%#x", block.Bellatrix.Body.ExecutionPayloadHeader.FeeRecipient)
			if actual != f.feeRecipientAddress {
				log.Warn(ctx, "Proposing block with unexpected fee recipient address", nil,
					z.Str("expected", f.feeRecipientAddress), z.Str("actual", actual))
			}
		}

		coreBlock, err := core.NewVersionedBlindedBeaconBlock(block)
		if err != nil {
			return nil, errors.Wrap(err, "new block")
		}

		resp[pubkey] = coreBlock
	}

	return resp, nil
}
