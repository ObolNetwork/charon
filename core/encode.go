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

package core

import (
	"encoding/json"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"

	"github.com/obolnetwork/charon/app/errors"
)

// DecodeAttesterFetchArg returns the attester duty from the encoded FetchArg.
func DecodeAttesterFetchArg(fetchArg FetchArg) (*eth2v1.AttesterDuty, error) {
	attDuty := new(eth2v1.AttesterDuty)
	err := json.Unmarshal(fetchArg, attDuty)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal attester duty")
	}

	return attDuty, nil
}

// EncodeAttesterFetchArg returns the attester duty as an encoded FetchArg.
func EncodeAttesterFetchArg(attDuty *eth2v1.AttesterDuty) (FetchArg, error) {
	b, err := json.Marshal(attDuty)
	if err != nil {
		return nil, errors.Wrap(err, "marshal attester duty")
	}

	return b, nil
}

// DecodeProposerFetchArg returns the proposer duty from the encoded FetchArg.
func DecodeProposerFetchArg(fetchArg FetchArg) (*eth2v1.ProposerDuty, error) {
	proDuty := new(eth2v1.ProposerDuty)
	err := json.Unmarshal(fetchArg, proDuty)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal proposer duty")
	}

	return proDuty, nil
}

// EncodeProposerFetchArg returns the proposer duty as an encoded FetchArg.
func EncodeProposerFetchArg(proDuty *eth2v1.ProposerDuty) (FetchArg, error) {
	b, err := json.Marshal(proDuty)
	if err != nil {
		return nil, errors.Wrap(err, "marshal proposer duty")
	}

	return b, nil
}
