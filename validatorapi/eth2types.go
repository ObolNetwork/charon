package validatorapi

import (
	"encoding/json"
	"strconv"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
)

// errorResponse an error response from the beacon-node api.
// See https://ethereum.github.io/beacon-APIs.
type errorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	// TODO(corver): Maybe add stacktraces field for debugging.
}

// attesterDutiesResponse defines the response to the getAttesterDuties endpoint.
// See https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi/getAttesterDuties.
type attesterDutiesResponse struct {
	DependentRoot eth2p0.Root            `json:"dependent_root"`
	Data          []*eth2v1.AttesterDuty `json:"data"`
}

// attesterDutiesRequest defines the request to the getAttesterDuties endpoint.
// See https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi/getAttesterDuties.
type attesterDutiesRequest []eth2p0.ValidatorIndex

func (r *attesterDutiesRequest) UnmarshalJSON(bytes []byte) error {
	var strints []string

	if err := json.Unmarshal(bytes, &strints); err != nil {
		return err
	}

	for _, strint := range strints {
		i, err := strconv.ParseUint(strint, 10, 64)
		if err != nil {
			return err
		}
		*r = append(*r, eth2p0.ValidatorIndex(i))
	}

	return nil
}
