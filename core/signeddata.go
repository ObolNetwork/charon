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
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
)

var (
	_ SignedData = VersionedSignedBeaconBlock{}
	_ SignedData = Attestation{}
	_ SignedData = Signature{}
	_ SignedData = SignedVoluntaryExit{}
)

// NewVersionedSignedBeaconBlock validates and returns a new wrapped VersionedSignedBeaconBlock.
func NewVersionedSignedBeaconBlock(block *spec.VersionedSignedBeaconBlock) (VersionedSignedBeaconBlock, error) {
	switch block.Version {
	case spec.DataVersionPhase0:
		if block.Phase0 == nil {
			return VersionedSignedBeaconBlock{}, errors.New("no phase0 block")
		}
	case spec.DataVersionAltair:
		if block.Altair == nil {
			return VersionedSignedBeaconBlock{}, errors.New("no altair block")
		}
	case spec.DataVersionBellatrix:
		if block.Bellatrix == nil {
			return VersionedSignedBeaconBlock{}, errors.New("no bellatrix block")
		}
	default:
		return VersionedSignedBeaconBlock{}, errors.New("unknown version")
	}

	return VersionedSignedBeaconBlock{VersionedSignedBeaconBlock: *block}, nil
}

// NewPartialVersionedSignedBeaconBlock is a convenience function that returns a new partial signed block.
func NewPartialVersionedSignedBeaconBlock(block *spec.VersionedSignedBeaconBlock, shareIdx int) (ParSignedData2, error) {
	wrap, err := NewVersionedSignedBeaconBlock(block)
	if err != nil {
		return ParSignedData2{}, err
	}

	return ParSignedData2{
		SignedData: wrap,
		ShareIdx:   shareIdx,
	}, nil
}

// VersionedSignedBeaconBlock is a signed versioned beacon block and implements SignedData.
type VersionedSignedBeaconBlock struct {
	spec.VersionedSignedBeaconBlock // Could subtype instead of embed, but aligning with Attestation that cannot subtype.
}

func (b VersionedSignedBeaconBlock) Signature() Signature {
	switch b.Version {
	case spec.DataVersionPhase0:
		return SigFromETH2(b.Phase0.Signature)
	case spec.DataVersionAltair:
		return SigFromETH2(b.Altair.Signature)
	case spec.DataVersionBellatrix:
		return SigFromETH2(b.Bellatrix.Signature)
	default:
		panic("unknown version") // Note this is avoided by using `NewVersionedSignedBeaconBlock`.
	}
}

func (b VersionedSignedBeaconBlock) SetSignature(sig Signature) (SignedData, error) {
	// Make a copy by serialising (it contains pointers)
	bytes, err := b.MarshalJSON()
	if err != nil {
		return nil, errors.Wrap(err, "marshal block")
	}

	var resp VersionedSignedBeaconBlock
	if err := json.Unmarshal(bytes, &resp); err != nil {
		return nil, errors.Wrap(err, "unmarshal block")
	}

	switch b.Version {
	case spec.DataVersionPhase0:
		resp.Phase0.Signature = sig.ToETH2()
	case spec.DataVersionAltair:
		resp.Altair.Signature = sig.ToETH2()
	case spec.DataVersionBellatrix:
		resp.Bellatrix.Signature = sig.ToETH2()
	default:
		panic("unknown version") // Note this is avoided by using `NewVersionedSignedBeaconBlock`.
	}

	return resp, nil
}

func (b VersionedSignedBeaconBlock) MarshalJSON() ([]byte, error) {
	var marshaller json.Marshaler
	switch b.Version {
	case spec.DataVersionPhase0:
		marshaller = b.VersionedSignedBeaconBlock.Phase0
	case spec.DataVersionAltair:
		marshaller = b.VersionedSignedBeaconBlock.Altair
	case spec.DataVersionBellatrix:
		marshaller = b.VersionedSignedBeaconBlock.Bellatrix
	default:
		return nil, errors.New("unknown version")
	}

	block, err := marshaller.MarshalJSON()
	if err != nil {
		return nil, errors.Wrap(err, "marshal block")
	}

	resp, err := json.Marshal(versionedSignedBeaconBlockJSON{
		Version: int(b.Version),
		Block:   block,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal wrapper")
	}

	return resp, nil
}

func (b *VersionedSignedBeaconBlock) UnmarshalJSON(input []byte) error {
	var raw versionedSignedBeaconBlockJSON
	if err := json.Unmarshal(input, &raw); err != nil {
		return errors.Wrap(err, "unmarshal block")
	}

	resp := spec.VersionedSignedBeaconBlock{Version: spec.DataVersion(raw.Version)}
	switch resp.Version {
	case spec.DataVersionPhase0:
		block := new(eth2p0.SignedBeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal phase0")
		}
		resp.Phase0 = block
	case spec.DataVersionAltair:
		block := new(altair.SignedBeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal altair")
		}
		resp.Altair = block
	case spec.DataVersionBellatrix:
		block := new(bellatrix.SignedBeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal bellatrix")
		}
		resp.Bellatrix = block
	default:
		return errors.New("unknown version")
	}

	b.VersionedSignedBeaconBlock = resp

	return nil
}

type versionedSignedBeaconBlockJSON struct {
	Version int
	Block   json.RawMessage
}

// NewAttestation is a convenience function that returns a new wrapped attestation.
func NewAttestation(att *eth2p0.Attestation) Attestation {
	return Attestation{Attestation: *att}
}

// NewPartialAttestation is a convenience function that returns a new partially signed attestation.
func NewPartialAttestation(att *eth2p0.Attestation, shareIdx int) ParSignedData2 {
	return ParSignedData2{
		SignedData: NewAttestation(att),
		ShareIdx:   shareIdx,
	}
}

// Attestation is a signed attestation and implements SignedData.
type Attestation struct {
	eth2p0.Attestation
}

func (a Attestation) Signature() Signature {
	return SigFromETH2(a.Attestation.Signature)
}

func (a Attestation) SetSignature(sig Signature) (SignedData, error) {
	a.Attestation.Signature = sig.ToETH2()
	return Attestation{Attestation: a.Attestation}, nil
}

func (a Attestation) MarshalJSON() ([]byte, error) {
	return a.Attestation.MarshalJSON()
}

func (a *Attestation) UnmarshalJSON(b []byte) error {
	return a.Attestation.UnmarshalJSON(b)
}

// NewSignedVoluntaryExit is a convenience function that returns a new signed voluntary exit.
func NewSignedVoluntaryExit(exit *eth2p0.SignedVoluntaryExit) SignedVoluntaryExit {
	return SignedVoluntaryExit{SignedVoluntaryExit: *exit}
}

// NewPartialSignedVoluntaryExit is a convenience function that returns a new partially signed voluntary exit.
func NewPartialSignedVoluntaryExit(exit *eth2p0.SignedVoluntaryExit, shareIdx int) ParSignedData2 {
	return ParSignedData2{
		SignedData: NewSignedVoluntaryExit(exit),
		ShareIdx:   shareIdx,
	}
}

type SignedVoluntaryExit struct {
	eth2p0.SignedVoluntaryExit
}

func (a SignedVoluntaryExit) Signature() Signature {
	return SigFromETH2(a.SignedVoluntaryExit.Signature)
}

func (a SignedVoluntaryExit) SetSignature(sig Signature) (SignedData, error) {
	a.SignedVoluntaryExit.Signature = sig.ToETH2()
	return SignedVoluntaryExit{SignedVoluntaryExit: a.SignedVoluntaryExit}, nil
}

func (a SignedVoluntaryExit) MarshalJSON() ([]byte, error) {
	return a.SignedVoluntaryExit.MarshalJSON()
}

func (a *SignedVoluntaryExit) UnmarshalJSON(b []byte) error {
	return a.SignedVoluntaryExit.UnmarshalJSON(b)
}
