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

// DecodeProposerFetchArg return the proposer duty from the encoded FetchArg.
func DecodeProposerFetchArg(fetchArg FetchArg) (*eth2v1.ProposerDuty, error) {
	proDuty := new(eth2v1.ProposerDuty)
	err := json.Unmarshal(fetchArg, proDuty)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal proposer duty")
	}

	return proDuty, nil
}

// EncodeProposerFetchArg return the proposer duty as an encoded FetchArg.
func EncodeProposerFetchArg(proDuty *eth2v1.ProposerDuty) (FetchArg, error) {
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

// EncodeAttestationParSignedData returns the attestation as an encoded ParSignedData.
func EncodeAttestationParSignedData(att *eth2p0.Attestation, shareIdx int) (ParSignedData, error) {
	data, err := json.Marshal(att)
	if err != nil {
		return ParSignedData{}, errors.Wrap(err, "marshal attestation")
	}

	return ParSignedData{
		Data:      data,
		Signature: SigFromETH2(att.Signature), // Copy the signature
		ShareIdx:  shareIdx,
	}, nil
}

// EncodeVoluntaryExitParSignedData encodes to json to pass between Go components losing typing,
// returns a ParSignedData that contains json.
// WARNING: using this method makes you lose Golang type safety features.
func EncodeVoluntaryExitParSignedData(ve *eth2p0.SignedVoluntaryExit, shareIdx int) (ParSignedData, error) {
	data, err := json.Marshal(ve)
	if err != nil {
		return ParSignedData{}, errors.Wrap(err, "json marshal signed voluntary exit")
	}

	return ParSignedData{
		Data:      data,
		Signature: SigFromETH2(ve.Signature),
		ShareIdx:  shareIdx,
	}, nil
}

// DecodeAttestationParSignedData returns the attestation from the encoded ParSignedData.
func DecodeAttestationParSignedData(data ParSignedData) (*eth2p0.Attestation, error) {
	att := new(eth2p0.Attestation)
	err := json.Unmarshal(data.Data, att)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal attestation")
	}

	return att, nil
}

// DecodeSignedVoluntaryExitParSignedData json decode signed voluntary exit from the previous
// Golang component.
func DecodeSignedVoluntaryExitParSignedData(data ParSignedData) (*eth2p0.SignedVoluntaryExit, error) {
	ve := new(eth2p0.SignedVoluntaryExit)
	err := json.Unmarshal(data.Data, ve)
	if err != nil {
		return nil, errors.Wrap(err, "json decoding signed voluntary exit")
	}

	return ve, nil
}

// EncodeAttestationAggSignedData returns the attestation as an encoded AggSignedData.
func EncodeAttestationAggSignedData(att *eth2p0.Attestation) (AggSignedData, error) {
	data, err := json.Marshal(att)
	if err != nil {
		return AggSignedData{}, errors.Wrap(err, "marshal attestation")
	}

	return AggSignedData{
		Data:      data,
		Signature: SigFromETH2(att.Signature), // Copy the signature
	}, nil
}

// DecodeAttestationAggSignedData returns the attestation from the encoded AggSignedData.
func DecodeAttestationAggSignedData(data AggSignedData) (*eth2p0.Attestation, error) {
	att := new(eth2p0.Attestation)
	err := json.Unmarshal(data.Data, att)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal attestation")
	}

	return att, nil
}

// EncodeRandaoParSignedData returns the RANDAO reveal as an encoded ParSignedData.
func EncodeRandaoParSignedData(randao eth2p0.BLSSignature, shareIdx int) ParSignedData {
	return ParSignedData{
		Data:      nil, // Randao is just a signature, so keeping data nil.
		Signature: SigFromETH2(randao),
		ShareIdx:  shareIdx,
	}
}

// DecodeRandaoParSignedData returns the RANDAO reveal from the encoded ParSignedData as BLS signature.
func DecodeRandaoParSignedData(data ParSignedData) eth2p0.BLSSignature {
	return data.Signature.ToETH2()
}

// EncodeRandaoAggSignedData returns the RANDAO reveal as an encoded AggSignedData.
func EncodeRandaoAggSignedData(randao eth2p0.BLSSignature) AggSignedData {
	return AggSignedData{
		Data:      nil, // Randao is just a signature, so keeping data nil.
		Signature: SigFromETH2(randao),
	}
}

// DecodeRandaoAggSignedData returns the RANDAO reveal from the encoded AggSignedData as BLS Signature.
func DecodeRandaoAggSignedData(data AggSignedData) eth2p0.BLSSignature {
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

// EncodeBlockParSignedData returns the partially signed block data as an encoded ParSignedData.
func EncodeBlockParSignedData(block *spec.VersionedSignedBeaconBlock, shareIdx int) (ParSignedData, error) {
	data, err := json.Marshal(block)
	if err != nil {
		return ParSignedData{}, errors.Wrap(err, "marshal block")
	}

	var sig Signature
	switch block.Version {
	case spec.DataVersionPhase0:
		if block.Phase0 == nil {
			return ParSignedData{}, errors.New("no phase0 block")
		}
		sig = SigFromETH2(block.Phase0.Signature)
	case spec.DataVersionAltair:
		if block.Altair == nil {
			return ParSignedData{}, errors.New("no altair block")
		}
		sig = SigFromETH2(block.Altair.Signature)
	case spec.DataVersionBellatrix:
		if block.Bellatrix == nil {
			return ParSignedData{}, errors.New("no bellatrix block")
		}
		sig = SigFromETH2(block.Bellatrix.Signature)
	default:
		return ParSignedData{}, errors.New("invalid block")
	}

	return ParSignedData{
		Data:      data,
		Signature: sig,
		ShareIdx:  shareIdx,
	}, nil
}

// DecodeBlockParSignedData returns the partially signed block data from the encoded ParSignedData.
func DecodeBlockParSignedData(data ParSignedData) (*spec.VersionedSignedBeaconBlock, error) {
	block := new(spec.VersionedSignedBeaconBlock)
	err := json.Unmarshal(data.Data, block)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal block")
	}

	return block, nil
}

// EncodeBlockAggSignedData returns the partially signed block data as an encoded AggSignedData.
func EncodeBlockAggSignedData(block *spec.VersionedSignedBeaconBlock) (AggSignedData, error) {
	data, err := json.Marshal(block)
	if err != nil {
		return AggSignedData{}, errors.Wrap(err, "marshal signed block")
	}

	var sig Signature
	switch block.Version {
	case spec.DataVersionPhase0:
		if block.Phase0 == nil {
			return AggSignedData{}, errors.New("no phase0 block")
		}
		sig = SigFromETH2(block.Phase0.Signature)
	case spec.DataVersionAltair:
		if block.Altair == nil {
			return AggSignedData{}, errors.New("no altair block")
		}
		sig = SigFromETH2(block.Altair.Signature)
	case spec.DataVersionBellatrix:
		if block.Bellatrix == nil {
			return AggSignedData{}, errors.New("no bellatrix block")
		}
		sig = SigFromETH2(block.Bellatrix.Signature)
	default:
		return AggSignedData{}, errors.New("invalid block")
	}

	return AggSignedData{
		Data:      data,
		Signature: sig,
	}, nil
}

// DecodeBlockAggSignedData returns the partially signed block data from the encoded AggSignedData.
func DecodeBlockAggSignedData(data AggSignedData) (*spec.VersionedSignedBeaconBlock, error) {
	block := new(spec.VersionedSignedBeaconBlock)
	err := json.Unmarshal(data.Data, block)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal signed block")
	}

	return block, nil
}
