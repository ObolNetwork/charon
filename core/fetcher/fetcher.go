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

	eth2client "github.com/attestantio/go-eth2-client"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

// eth2Provider defines the eth2 provider subset used by this package.
type eth2Provider interface {
	eth2client.AttestationDataProvider
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
	eth2Cl eth2Provider
	subs   []func(context.Context, core.Duty, core.UnsignedDataSet) error
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

	//nolint: exhaustive // Default case is exhaustive
	switch duty.Type {
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

// fetchAttesterData returns the fetched attestation data set for committees and validators in the arg set.
func (f *Fetcher) fetchAttesterData(ctx context.Context, slot int64, argSet core.FetchArgSet,
) (core.UnsignedDataSet, error) {
	valsByComm := make(map[eth2p0.CommitteeIndex][]core.PubKey)

	for val, arg := range argSet {
		attDuty, err := core.DecodeAttesterFetchArg(arg)
		if err != nil {
			return nil, err
		}

		valsByComm[attDuty.CommitteeIndex] = append(valsByComm[attDuty.CommitteeIndex], val)
	}

	resp := make(core.UnsignedDataSet)
	for commIdx, pubkeys := range valsByComm {
		attData, err := f.eth2Cl.AttestationData(ctx, eth2p0.Slot(uint64(slot)), commIdx)
		if err != nil {
			return nil, err
		}

		dutyData, err := core.EncodeAttesterUnsingedData(attData)
		if err != nil {
			return nil, errors.Wrap(err, "unmarhsal json")
		}

		// TODO(corver): Attestion data for the same committee is identical, could optimise this.
		for _, pubkey := range pubkeys {
			resp[pubkey] = dutyData
		}
	}

	return resp, nil
}
