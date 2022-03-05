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

package core

import (
	"encoding/json"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
)

// DecodeAttesterFetchArg return the attester duty from the encoded FetchArg.
func DecodeAttesterFetchArg(fetchArg FetchArg) (*eth2v1.AttesterDuty, error) {
	attDuty := new(eth2v1.AttesterDuty)
	err := json.Unmarshal(fetchArg, attDuty)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal attester duty")
	}

	return attDuty, nil
}

// EncodeAttesterFetchArg return the attester duty as an encoded FetchArg.
func EncodeAttesterFetchArg(attDuty *eth2v1.AttesterDuty) (FetchArg, error) {
	b, err := json.Marshal(attDuty)
	if err != nil {
		return nil, errors.Wrap(err, "marshal attester duty")
	}

	return b, nil
}

// DecodeAttesterUnsignedData return the attestation data from the encoded UnsignedData.
func DecodeAttesterUnsignedData(unsignedData UnsignedData) (*AttestationData, error) {
	attData := new(AttestationData)
	err := json.Unmarshal(unsignedData, attData)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal attestation data")
	}

	return attData, nil
}

// EncodeAttesterUnsignedData returns the attestation data as an encoded UnsignedData.
func EncodeAttesterUnsignedData(attData *AttestationData) (UnsignedData, error) {
	b, err := json.Marshal(attData)
	if err != nil {
		return nil, errors.Wrap(err, "marshal attestation data")
	}

	return b, nil
}

// EncodeAttestationParSignedData returns the attestation as an encoded ParSignedData.
func EncodeAttestationParSignedData(att *eth2p0.Attestation, index int) (ParSignedData, error) {
	data, err := json.Marshal(att)
	if err != nil {
		return ParSignedData{}, errors.Wrap(err, "marshal attestation")
	}

	return ParSignedData{
		Data:      data,
		Signature: att.Signature[:],
		Index:     index,
	}, nil
}

// DecodeAttestationParSignedData returns the attestation as an encoded ParSignedData.
func DecodeAttestationParSignedData(data ParSignedData) (*eth2p0.Attestation, error) {
	att := new(eth2p0.Attestation)
	err := json.Unmarshal(data.Data, att)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal attestation")
	}

	return att, nil
}
