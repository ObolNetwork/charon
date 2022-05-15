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
	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
)

// DecodeAttesterDutyDefinition return the attester duty from the encoded DutyDefinition.
func DecodeAttesterDutyDefinition(fetchArg DutyDefinition) (*eth2v1.AttesterDuty, error) {
	attDuty := new(eth2v1.AttesterDuty)
	err := json.Unmarshal(fetchArg, attDuty)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal attester duty")
	}

	return attDuty, nil
}

// EncodeAttesterDutyDefinition return the attester duty as an encoded DutyDefinition.
func EncodeAttesterDutyDefinition(attDuty *eth2v1.AttesterDuty) (DutyDefinition, error) {
	b, err := json.Marshal(attDuty)
	if err != nil {
		return nil, errors.Wrap(err, "marshal attester duty")
	}

	return b, nil
}

// DecodeProposerDutyDefinition return the proposer duty from the encoded DutyDefinition.
func DecodeProposerDutyDefinition(fetchArg DutyDefinition) (*eth2v1.ProposerDuty, error) {
	proDuty := new(eth2v1.ProposerDuty)
	err := json.Unmarshal(fetchArg, proDuty)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal proposer duty")
	}

	return proDuty, nil
}

// EncodeProposerDutyDefinition return the proposer duty as an encoded DutyDefinition.
func EncodeProposerDutyDefinition(proDuty *eth2v1.ProposerDuty) (DutyDefinition, error) {
	b, err := json.Marshal(proDuty)
	if err != nil {
		return nil, errors.Wrap(err, "marshal proposer duty")
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

// EncodeAttestationShareSignedData returns the attestation as an encoded ShareSignedData.
func EncodeAttestationShareSignedData(att *eth2p0.Attestation, shareIdx int) (ShareSignedData, error) {
	data, err := json.Marshal(att)
	if err != nil {
		return ShareSignedData{}, errors.Wrap(err, "marshal attestation")
	}

	return ShareSignedData{
		Data:      data,
		Signature: SigFromETH2(att.Signature), // Copy the signature
		ShareIdx:  shareIdx,
	}, nil
}

// DecodeAttestationShareSignedData returns the attestation from the encoded ShareSignedData.
func DecodeAttestationShareSignedData(data ShareSignedData) (*eth2p0.Attestation, error) {
	att := new(eth2p0.Attestation)
	err := json.Unmarshal(data.Data, att)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal attestation")
	}

	return att, nil
}

// EncodeAttestationGroupSignedData returns the attestation as an encoded GroupSignedData.
func EncodeAttestationGroupSignedData(att *eth2p0.Attestation) (GroupSignedData, error) {
	data, err := json.Marshal(att)
	if err != nil {
		return GroupSignedData{}, errors.Wrap(err, "marshal attestation")
	}

	return GroupSignedData{
		Data:      data,
		Signature: SigFromETH2(att.Signature), // Copy the signature
	}, nil
}

// DecodeAttestationGroupSignedData returns the attestation from the encoded GroupSignedData.
func DecodeAttestationGroupSignedData(data GroupSignedData) (*eth2p0.Attestation, error) {
	att := new(eth2p0.Attestation)
	err := json.Unmarshal(data.Data, att)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal attestation")
	}

	return att, nil
}

// EncodeRandaoShareSignedData returns the RANDAO reveal as an encoded ShareSignedData.
func EncodeRandaoShareSignedData(randao eth2p0.BLSSignature, shareIdx int) ShareSignedData {
	return ShareSignedData{
		Data:      nil, // Randao is just a signature, so keeping data nil.
		Signature: SigFromETH2(randao),
		ShareIdx:  shareIdx,
	}
}

// DecodeRandaoShareSignedData returns the RANDAO reveal from the encoded ShareSignedData as BLS signature.
func DecodeRandaoShareSignedData(data ShareSignedData) eth2p0.BLSSignature {
	return data.Signature.ToETH2()
}

// EncodeRandaoGroupSignedData returns the RANDAO reveal as an encoded GroupSignedData.
func EncodeRandaoGroupSignedData(randao eth2p0.BLSSignature) GroupSignedData {
	return GroupSignedData{
		Data:      nil, // Randao is just a signature, so keeping data nil.
		Signature: SigFromETH2(randao),
	}
}

// DecodeRandaoGroupSignedData returns the RANDAO reveal from the encoded GroupSignedData as BLS Signature.
func DecodeRandaoGroupSignedData(data GroupSignedData) eth2p0.BLSSignature {
	return data.Signature.ToETH2()
}

// EncodeProposerUnsignedData returns the proposer data as an encoded UnsignedData.
func EncodeProposerUnsignedData(proData *spec.VersionedBeaconBlock) (UnsignedData, error) {
	b, err := json.Marshal(proData)
	if err != nil {
		return nil, errors.Wrap(err, "marshal proposer data")
	}

	return b, nil
}

// DecodeProposerUnsignedData returns the proposer data from the encoded UnsignedData.
func DecodeProposerUnsignedData(unsignedData UnsignedData) (*spec.VersionedBeaconBlock, error) {
	proData := new(spec.VersionedBeaconBlock)
	err := json.Unmarshal(unsignedData, proData)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal proposer data")
	}

	return proData, nil
}

// EncodeBlockShareSignedData returns the partially signed block data as an encoded ShareSignedData.
func EncodeBlockShareSignedData(block *spec.VersionedSignedBeaconBlock, shareIdx int) (ShareSignedData, error) {
	data, err := json.Marshal(block)
	if err != nil {
		return ShareSignedData{}, errors.Wrap(err, "marshal block")
	}

	var sig Signature
	switch block.Version {
	case spec.DataVersionPhase0:
		if block.Phase0 == nil {
			return ShareSignedData{}, errors.New("no phase0 block")
		}
		sig = SigFromETH2(block.Phase0.Signature)
	case spec.DataVersionAltair:
		if block.Altair == nil {
			return ShareSignedData{}, errors.New("no altair block")
		}
		sig = SigFromETH2(block.Altair.Signature)
	case spec.DataVersionBellatrix:
		if block.Bellatrix == nil {
			return ShareSignedData{}, errors.New("no bellatrix block")
		}
		sig = SigFromETH2(block.Bellatrix.Signature)
	default:
		return ShareSignedData{}, errors.New("invalid block")
	}

	return ShareSignedData{
		Data:      data,
		Signature: sig,
		ShareIdx:  shareIdx,
	}, nil
}

// DecodeBlockShareSignedData returns the partially signed block data from the encoded ShareSignedData.
func DecodeBlockShareSignedData(data ShareSignedData) (*spec.VersionedSignedBeaconBlock, error) {
	block := new(spec.VersionedSignedBeaconBlock)
	err := json.Unmarshal(data.Data, block)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal block")
	}

	return block, nil
}

// EncodeBlockGroupSignedData returns the partially signed block data as an encoded GroupSignedData.
func EncodeBlockGroupSignedData(block *spec.VersionedSignedBeaconBlock) (GroupSignedData, error) {
	data, err := json.Marshal(block)
	if err != nil {
		return GroupSignedData{}, errors.Wrap(err, "marshal signed block")
	}

	var sig Signature
	switch block.Version {
	case spec.DataVersionPhase0:
		if block.Phase0 == nil {
			return GroupSignedData{}, errors.New("no phase0 block")
		}
		sig = SigFromETH2(block.Phase0.Signature)
	case spec.DataVersionAltair:
		if block.Altair == nil {
			return GroupSignedData{}, errors.New("no altair block")
		}
		sig = SigFromETH2(block.Altair.Signature)
	case spec.DataVersionBellatrix:
		if block.Bellatrix == nil {
			return GroupSignedData{}, errors.New("no bellatrix block")
		}
		sig = SigFromETH2(block.Bellatrix.Signature)
	default:
		return GroupSignedData{}, errors.New("invalid block")
	}

	return GroupSignedData{
		Data:      data,
		Signature: sig,
	}, nil
}

// DecodeBlockGroupSignedData returns the partially signed block data from the encoded GroupSignedData.
func DecodeBlockGroupSignedData(data GroupSignedData) (*spec.VersionedSignedBeaconBlock, error) {
	block := new(spec.VersionedSignedBeaconBlock)
	err := json.Unmarshal(data.Data, block)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal signed block")
	}

	return block, nil
}
