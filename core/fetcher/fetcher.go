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

	eth2client "github.com/attestantio/go-eth2-client"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

// eth2Provider defines the eth2 provider subset used by this package.
type eth2Provider interface {
	eth2client.AttestationDataProvider
	eth2client.BeaconBlockProposalProvider
}

// New returns a new fetcher instance.
func New(eth2Svc eth2client.Service) (*Fetcher, error) {
	eth2Cl, ok := eth2Svc.(eth2Provider)
	if !ok {
		return nil, errors.New("invalid eth2 service")
	}

	return &Fetcher{
		eth2Cl: eth2Cl,
	}, nil
}

// Fetcher fetches proposed duty data.
type Fetcher struct {
	eth2Cl       eth2Provider
	subs         []func(context.Context, core.Duty, core.UnsignedDataSet) error
	aggSigDBFunc func(context.Context, core.Duty, core.PubKey) (core.SignedData, error)
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

// RegisterAggSigDB registers a function to get resolved aggregated signed data from the AggSigDB.
// Note: This is not thread safe should be called *before* Fetch.
func (f *Fetcher) RegisterAggSigDB(fn func(context.Context, core.Duty, core.PubKey) (core.SignedData, error)) {
	f.aggSigDBFunc = fn
}

// fetchAttesterData returns the fetched attestation data set for committees and validators in the arg set.
func (f *Fetcher) fetchAttesterData(ctx context.Context, slot int64, defSet core.DutyDefinitionSet,
) (core.UnsignedDataSet, error) {
	// We may have multiple validators in the same committee, use the same attestation data in that case.
	dataByCommIdx := make(map[eth2p0.CommitteeIndex]*eth2p0.AttestationData)

	resp := make(core.UnsignedDataSet)
	for pubkey, def := range defSet {
		attDuty, ok := def.(core.AttesterDefinition)
		if !ok {
			return nil, errors.New("invalid attester definition")
		}

		eth2AttData, ok := dataByCommIdx[attDuty.CommitteeIndex]
		if !ok {
			var err error
			eth2AttData, err = f.eth2Cl.AttestationData(ctx, eth2p0.Slot(uint64(slot)), attDuty.CommitteeIndex)
			if err != nil {
				return nil, err
			}

			dataByCommIdx[attDuty.CommitteeIndex] = eth2AttData
		}

		attData := core.AttestationData{
			Data: *eth2AttData,
			Duty: attDuty.AttesterDuty,
		}

		resp[pubkey] = attData
	}

	return resp, nil
}

func (f *Fetcher) fetchProposerData(ctx context.Context, slot int64, defSet core.DutyDefinitionSet) (core.UnsignedDataSet, error) {
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

		// TODO(dhruv): what to do with graffiti?
		// passing empty graffiti since it is not required in API
		var graffiti [32]byte
		block, err := f.eth2Cl.BeaconBlockProposal(ctx, eth2p0.Slot(uint64(slot)), randao, graffiti[:])
		if err != nil {
			return nil, err
		}

		coreBlock, err := core.NewVersionedBeaconBlock(block)
		if err != nil {
			return nil, errors.Wrap(err, "new block")
		}

		resp[pubkey] = coreBlock
	}

	return resp, nil
}
