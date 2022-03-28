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

// Package bcast provides the core workflow's broadcaster component that
// broadcasts/submits aggregated singed duty data to the beacon-node.
package bcast

import (
	"context"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
)

type eth2Provider interface {
	eth2client.AttestationsSubmitter
}

// New returns a new broadcaster instance.
func New(eth2Svc eth2client.Service) (Broadcaster, error) {
	eth2Cl, ok := eth2Svc.(eth2Provider)
	if !ok {
		return Broadcaster{}, errors.New("invalid eth2 service")
	}

	return Broadcaster{eth2Cl: eth2Cl}, nil
}

type Broadcaster struct {
	eth2Cl eth2Provider
}

// Broadcast broadcasts the aggregated signed duty data object to the beacon-node.
func (b Broadcaster) Broadcast(ctx context.Context, duty core.Duty,
	pubkey core.PubKey, aggData core.AggSignedData,
) (err error) {
	defer func() {
		if err == nil {
			instrumentDuty(duty, pubkey)
		}
	}()

	switch duty.Type {
	case core.DutyAttester:
		att, err := core.DecodeAttestationAggSignedData(aggData)
		if err != nil {
			return err
		}

		return b.eth2Cl.SubmitAttestations(ctx, []*eth2p0.Attestation{att})
	default:
		return errors.New("unsuppered duty type")
	}
}
