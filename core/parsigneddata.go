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

	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
)

var (
	_ ParSignedData = VersionedSignedBeaconBlock{}
	_ ParSignedData = Attestation{}
	_ ParSignedData = ParSig{}
	_ ParSignedData = SignedExit{}
)

func NewParSig(sig eth2p0.BLSSignature, shareIdx int) ParSig {
	return ParSig{BLSSignature: sig, shareIdx: shareIdx}
}

// ParSig is a partial signature that implements ParSignedData without additional data.
type ParSig struct {
	eth2p0.BLSSignature
	shareIdx int
}

func (ParSig) DataRoot() (eth2p0.Root, error) {
	// parsig (and randao) is just a signature, it doesn't have other data.
	return eth2p0.Root{}, nil
}

func (r ParSig) Signature() Signature {
	return SigFromETH2(r.BLSSignature)
}

func (r ParSig) ShareIdx() int {
	return r.shareIdx
}

func (ParSig) MarshalData() ([]byte, error) {
	return nil, nil
}

func (ParSig) AggSign(sig Signature) (AggSignedData, error) {
	return EncodeRandaoAggSignedData(sig.ToETH2()), nil
}

func NewVersionedSignedBeaconBlock(block *spec.VersionedSignedBeaconBlock, shareIdx int) (VersionedSignedBeaconBlock, error) {
	var sig Signature
	switch block.Version {
	case spec.DataVersionPhase0:
		if block.Phase0 == nil {
			return VersionedSignedBeaconBlock{}, errors.New("no phase0 block")
		}
		sig = SigFromETH2(block.Phase0.Signature)
	case spec.DataVersionAltair:
		if block.Altair == nil {
			return VersionedSignedBeaconBlock{}, errors.New("no altair block")
		}
		sig = SigFromETH2(block.Altair.Signature)
	case spec.DataVersionBellatrix:
		if block.Bellatrix == nil {
			return VersionedSignedBeaconBlock{}, errors.New("no bellatrix block")
		}
		sig = SigFromETH2(block.Bellatrix.Signature)
	default:
		return VersionedSignedBeaconBlock{}, errors.New("invalid block")
	}

	return VersionedSignedBeaconBlock{
		VersionedSignedBeaconBlock: *block,
		signature:                  sig,
		shareIdx:                   shareIdx,
	}, nil
}

// VersionedSignedBeaconBlock is a partially signed versioned beacon block and implements ParSignedData.
type VersionedSignedBeaconBlock struct {
	spec.VersionedSignedBeaconBlock
	signature Signature
	shareIdx  int
}

func (b VersionedSignedBeaconBlock) DataRoot() (eth2p0.Root, error) {
	return b.Root()
}

func (b VersionedSignedBeaconBlock) Signature() Signature {
	return b.signature
}

func (b VersionedSignedBeaconBlock) ShareIdx() int {
	return b.shareIdx
}

func (b VersionedSignedBeaconBlock) AggSign(sig Signature) (AggSignedData, error) {
	switch b.Version {
	case spec.DataVersionPhase0:
		if b.Phase0 == nil {
			return AggSignedData{}, errors.New("no phase0 block")
		}
		b.Phase0.Signature = sig.ToETH2()
	case spec.DataVersionAltair:
		if b.Altair == nil {
			return AggSignedData{}, errors.New("no altair block")
		}
		b.Altair.Signature = sig.ToETH2()
	case spec.DataVersionBellatrix:
		if b.Bellatrix == nil {
			return AggSignedData{}, errors.New("no bellatrix block")
		}
		b.Bellatrix.Signature = sig.ToETH2()
	default:
		return AggSignedData{}, errors.New("invalid block")
	}

	return EncodeBlockAggSignedData(&b.VersionedSignedBeaconBlock)
}

func (b VersionedSignedBeaconBlock) MarshalData() ([]byte, error) {
	var (
		resp []byte
		err  error
	)
	switch b.Version {
	case spec.DataVersionPhase0:
		if b.Phase0 == nil {
			return nil, errors.New("no phase0 block")
		}

		resp, err = json.Marshal(b.Phase0)
	case spec.DataVersionAltair:
		if b.Altair == nil {
			return nil, errors.New("no altair block")
		}

		resp, err = json.Marshal(b.Altair)
	case spec.DataVersionBellatrix:
		if b.Bellatrix == nil {
			return nil, errors.New("no bellatrix block")
		}

		resp, err = json.Marshal(b.Bellatrix)
	default:
		return nil, errors.New("invalid block")
	}

	if err != nil {
		return nil, errors.Wrap(err, "unmarshal block")
	}

	return resp, nil
}

func NewAttestation(a *eth2p0.Attestation, shareIdx int) Attestation {
	return Attestation{
		Attestation: *a,
		shareIdx:    shareIdx,
	}
}

// Attestation is a partially signed attestation and implements ParSignedData.
type Attestation struct {
	eth2p0.Attestation

	shareIdx int
}

func (a Attestation) DataRoot() (eth2p0.Root, error) {
	return a.Data.HashTreeRoot()
}

func (a Attestation) Signature() Signature {
	return SigFromETH2(a.Attestation.Signature)
}

func (a Attestation) ShareIdx() int {
	return a.shareIdx
}

func (a Attestation) AggSign(sig Signature) (AggSignedData, error) {
	a.Attestation.Signature = sig.ToETH2()
	return EncodeAttestationAggSignedData(&a.Attestation)
}

func (a Attestation) MarshalData() ([]byte, error) {
	return a.Attestation.MarshalJSON()
}

func NewSignedExit(a *eth2p0.SignedVoluntaryExit, shareIdx int) SignedExit {
	return SignedExit{
		SignedVoluntaryExit: *a,
		shareIdx:            shareIdx,
	}
}

type SignedExit struct {
	eth2p0.SignedVoluntaryExit
	shareIdx int
}

func (a SignedExit) DataRoot() (eth2p0.Root, error) {
	return a.Message.HashTreeRoot()
}

func (a SignedExit) Signature() Signature {
	return SigFromETH2(a.SignedVoluntaryExit.Signature)
}

func (a SignedExit) ShareIdx() int {
	return a.shareIdx
}

func (a SignedExit) AggSign(sig Signature) (AggSignedData, error) {
	a.SignedVoluntaryExit.Signature = sig.ToETH2()
	return EncodeExitAggSignedData(&a.SignedVoluntaryExit)
}

func (a SignedExit) MarshalData() ([]byte, error) {
	return a.SignedVoluntaryExit.MarshalJSON()
}
