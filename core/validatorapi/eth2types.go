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

package validatorapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
)

// errorResponse an error response from the beacon-node api.
// See https://ethereum.github.io/beacon-APIs.
type errorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	// TODO(corver): Maybe add stacktraces field for debugging.
}

// valIndexesJSON defines the request to the getAttesterDuties and getSyncCommitteeDuties endpoint.
// See https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi/getAttesterDuties and
// https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi/getSyncCommitteeDuties.
type valIndexesJSON []eth2p0.ValidatorIndex

func (r *valIndexesJSON) UnmarshalJSON(bytes []byte) error {
	// First try normal json number array
	var ints []uint64
	if err := json.Unmarshal(bytes, &ints); err == nil {
		for _, i := range ints {
			*r = append(*r, eth2p0.ValidatorIndex(i))
		}

		return nil
	}

	// Then try string json number array
	var strints []string
	if err := json.Unmarshal(bytes, &strints); err != nil {
		return errors.Wrap(err, "unmarshal slice")
	}

	for _, strint := range strints {
		i, err := strconv.ParseUint(strint, 10, 64)
		if err != nil {
			return errors.Wrap(err, "parse index")
		}
		*r = append(*r, eth2p0.ValidatorIndex(i))
	}

	return nil
}

// attesterDutiesResponse defines the response to the getAttesterDuties endpoint.
// See https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi/getAttesterDuties.
type attesterDutiesResponse struct {
	DependentRoot       root                   `json:"dependent_root"`
	Data                []*eth2v1.AttesterDuty `json:"data"`
	ExecutionOptimistic bool                   `json:"execution_optimistic"`
}

// proposerDutiesResponse defines the response to the getAttesterDuties endpoint.
// See https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi/getProposerDuties.
type proposerDutiesResponse struct {
	DependentRoot       root                   `json:"dependent_root"`
	Data                []*eth2v1.ProposerDuty `json:"data"`
	ExecutionOptimistic bool                   `json:"execution_optimistic"`
}

type proposeBlockResponsePhase0 struct {
	Version string              `json:"version"`
	Data    *eth2p0.BeaconBlock `json:"data"`
}

type proposeBlockResponseAltair struct {
	Version string              `json:"version"`
	Data    *altair.BeaconBlock `json:"data"`
}

type proposeBlockResponseBellatrix struct {
	Version string                 `json:"version"`
	Data    *bellatrix.BeaconBlock `json:"data"`
}

type proposeBlindedBlockResponseBellatrix struct {
	Version string                            `json:"version"`
	Data    *eth2bellatrix.BlindedBeaconBlock `json:"data"`
}

type proposeBlindedBlockResponseCapella struct {
	Version string                          `json:"version"`
	Data    *eth2capella.BlindedBeaconBlock `json:"data"`
}

type proposeBlockResponseCapella struct {
	Version string               `json:"version"`
	Data    *capella.BeaconBlock `json:"data"`
}

type validatorsResponse struct {
	Data []v1Validator `json:"data"`
}

type validatorResponse struct {
	Data v1Validator `json:"data"`
}

type aggregateBeaconCommitteeSelectionsJSON struct {
	Data []*eth2exp.BeaconCommitteeSelection `json:"data"`
}

type aggregateSyncCommitteeSelectionsJSON struct {
	Data []*eth2exp.SyncCommitteeSelection `json:"data"`
}

// root wraps eth2p0 root adding proper json marshalling.
type root eth2p0.Root

func (r root) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%#x"`, r)), nil
}

// v1Validator wraps eth2v1 Validator proper json marshalling of status.
type v1Validator eth2v1.Validator

func (v v1Validator) MarshalJSON() ([]byte, error) {
	cast := eth2v1.Validator(v)
	b, err := json.Marshal(&cast)
	if err != nil {
		return nil, errors.Wrap(err, "marshal wrapped validator")
	}

	return bytes.ToLower(b), nil // ValidatorState must be lower case.
}

// syncCommitteeDutiesResponse defines the response to the getSyncCommitteeDuties endpoint.
// See: https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi/getSyncCommitteeDuties.
type syncCommitteeDutiesResponse struct {
	Data []*eth2v1.SyncCommitteeDuty `json:"data"`
}

// syncCommitteeContributionResponse defines the response to the syncCommitteeContribution endpoint.
// See: https://ethereum.github.io/beacon-APIs/#/Validator/produceSyncCommitteeContribution
type syncCommitteeContributionResponse struct {
	Data *altair.SyncCommitteeContribution `json:"data"`
}

// nodeVersionResponse defines the response to the node version endpoint.
// See: https://ethereum.github.io/beacon-APIs/#/Node/getNodeVersion
type nodeVersionResponse struct {
	Data struct {
		Version string `json:"version"`
	} `json:"data"`
}
