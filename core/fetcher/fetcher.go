// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fetcher

import (
	"context"
	"crypto/rand"

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
	aggSigDBFunc func(context.Context, core.Duty, core.PubKey) (core.AggSignedData, error)
}

// Subscribe registers a callback for fetched duties.
// Note this is not thread safe should be called *before* Fetch.
func (f *Fetcher) Subscribe(fn func(context.Context, core.Duty, core.UnsignedDataSet) error) {
	f.subs = append(f.subs, fn)
}

// Fetch triggers fetching of a proposed duty data set.
func (f *Fetcher) Fetch(ctx context.Context, duty core.Duty, argSet core.FetchArgSet) error {
	var (
		unsignedSet core.UnsignedDataSet
		err         error
	)

	switch duty.Type {
	case core.DutyProposer:
		unsignedSet, err = f.fetchProposerData(ctx, duty.Slot, argSet)
		if err != nil {
			return errors.Wrap(err, "fetch proposer data")
		}
	case core.DutyAttester:
		unsignedSet, err = f.fetchAttesterData(ctx, duty.Slot, argSet)
		if err != nil {
			return errors.Wrap(err, "fetch attester data")
		}
	default:
		return errors.New("unsupported duty type", z.Str("type", duty.Type.String()))
	}

	for _, sub := range f.subs {
		err := sub(ctx, duty, unsignedSet)
		if err != nil {
			return err
		}
	}

	return nil
}

func (f *Fetcher) RegisterAggSigDB(fn func(context.Context, core.Duty, core.PubKey) (core.AggSignedData, error)) {
	f.aggSigDBFunc = fn
}

// fetchAttesterData returns the fetched attestation data set for committees and validators in the arg set.
func (f *Fetcher) fetchAttesterData(ctx context.Context, slot int64, argSet core.FetchArgSet,
) (core.UnsignedDataSet, error) {
	// We may have multiple validators in the same committee, use the same attestation data in that case.
	dataByCommIdx := make(map[eth2p0.CommitteeIndex]*eth2p0.AttestationData)

	resp := make(core.UnsignedDataSet)
	for pubkey, fetchArg := range argSet {
		attDuty, err := core.DecodeAttesterFetchArg(fetchArg)
		if err != nil {
			return nil, err
		}

		eth2AttData, ok := dataByCommIdx[attDuty.CommitteeIndex]
		if !ok {
			eth2AttData, err = f.eth2Cl.AttestationData(ctx, eth2p0.Slot(uint64(slot)), attDuty.CommitteeIndex)
			if err != nil {
				return nil, err
			}

			dataByCommIdx[attDuty.CommitteeIndex] = eth2AttData
		}

		attData := &core.AttestationData{
			Data: *eth2AttData,
			Duty: *attDuty,
		}

		dutyData, err := core.EncodeAttesterUnsignedData(attData)
		if err != nil {
			return nil, errors.Wrap(err, "unmarhsal json")
		}

		resp[pubkey] = dutyData
	}

	return resp, nil
}

func (f *Fetcher) fetchProposerData(ctx context.Context, slot int64, argSet core.FetchArgSet) (core.UnsignedDataSet, error) {
	resp := make(core.UnsignedDataSet)
	for pubkey, fetchArg := range argSet {
		proDuty, err := core.DecodeProposerFetchArg(fetchArg)
		if err != nil {
			return nil, err
		}

		// Fetch previously aggregated randao reveal from AggSigDB
		dutyRandao := core.Duty{
			Slot: slot,
			Type: core.DutyRandao,
		}
		randao, err := f.aggSigDBFunc(ctx, dutyRandao, pubkey)
		if err != nil {
			return nil, err
		}
		randaoEth2 := core.DecodeRandaoAggSignedData(randao)

		// TODO(dhruv): what to do with graffiti? This will make this BeaconBlock unique for this charon node
		// passing randam graffiti since it is not required in API
		var graffiti [32]byte
		_, _ = rand.Read(graffiti[:])
		eth2ProData, err := f.eth2Cl.BeaconBlockProposal(ctx, eth2p0.Slot(uint64(slot)), randaoEth2, graffiti[:])
		if err != nil {
			return nil, err
		}
		proData := &core.ProposerData{
			Data: *eth2ProData.Phase0,
			Duty: *proDuty,
		}

		dutyData, err := core.EncodeProposerUnsignedData(proData)
		if err != nil {
			return nil, errors.Wrap(err, "encode proposer data")
		}

		resp[pubkey] = dutyData
	}

	return resp, nil
}
