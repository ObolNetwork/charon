// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// DistValidator is a distributed validator (1x32ETH) managed by the cluster.
type DistValidator struct {
	// PubKey is the distributed validator group public key.
	PubKey []byte `json:"distributed_public_key"  ssz:"Bytes48" lock_hash:"0"`

	// PubShares are the public keys corresponding to each node's secret key share.
	// It can be used to verify a partial signature created by any node in the cluster.
	PubShares [][]byte `json:"public_shares,omitempty" ssz:"CompositeList[256],Bytes48" lock_hash:"1"`

	// DepositData is the validator deposit data.
	DepositData DepositData `json:"deposit_data,omitempty" ssz:"Composite" lock_hash:"2"`

	// BuilderRegistration is the pre-generated signed validator builder registration.
	BuilderRegistration BuilderRegistration `json:"builder_registration,omitempty" ssz:"Composite" lock_hash:"3"`
}

// PublicKey returns the validator BLS group public key.
func (v DistValidator) PublicKey() (tbls.PublicKey, error) {
	return tblsconv.PubkeyFromBytes(v.PubKey)
}

// PublicKeyHex returns the validator hex group public key.
func (v DistValidator) PublicKeyHex() string {
	return to0xHex(v.PubKey)
}

// PublicShare returns a peer's threshold BLS public share.
func (v DistValidator) PublicShare(peerIdx int) (tbls.PublicKey, error) {
	return tblsconv.PubkeyFromBytes(v.PubShares[peerIdx])
}

// ZeroRegistration returns a true if the validator has zero valued registration.
func (v DistValidator) ZeroRegistration() bool {
	reg := v.BuilderRegistration

	return len(reg.Signature) == 0 &&
		len(reg.Message.PubKey) == 0 &&
		len(reg.Message.FeeRecipient) == 0 &&
		reg.Message.GasLimit == 0 &&
		reg.Message.Timestamp.IsZero()
}

// Eth2Registration returns the validator's Eth2 registration.
func (v DistValidator) Eth2Registration() (*eth2api.VersionedSignedValidatorRegistration, error) {
	reg := v.BuilderRegistration

	if len(reg.Signature) != len(eth2p0.BLSSignature{}) ||
		len(reg.Message.PubKey) != len(eth2p0.BLSPubKey{}) ||
		len(reg.Message.FeeRecipient) != len(bellatrix.ExecutionAddress{}) ||
		reg.Message.GasLimit == 0 ||
		reg.Message.Timestamp.IsZero() {
		return nil, errors.New("invalid registration")
	}

	return &eth2api.VersionedSignedValidatorRegistration{
		Version: eth2spec.BuilderVersionV1,
		V1: &eth2v1.SignedValidatorRegistration{
			Message: &eth2v1.ValidatorRegistration{
				FeeRecipient: bellatrix.ExecutionAddress(reg.Message.FeeRecipient),
				GasLimit:     uint64(reg.Message.GasLimit),
				Timestamp:    reg.Message.Timestamp,
				Pubkey:       eth2p0.BLSPubKey(reg.Message.PubKey),
			},
			Signature: eth2p0.BLSSignature(reg.Signature),
		},
	}, nil
}

// distValidatorJSONv1x1 is the json formatter of DistValidator for versions v1.0.0 and v1.1.0.
type distValidatorJSONv1x1 struct {
	PubKey              ethHex   `json:"distributed_public_key"`
	PubShares           [][]byte `json:"public_shares,omitempty"`
	FeeRecipientAddress ethHex   `json:"fee_recipient_address,omitempty"`
}

// distValidatorJSONv1x2to5 is the json formatter of DistValidator for versions v1.2.0 to v1.5.0.
type distValidatorJSONv1x2to5 struct {
	PubKey              ethHex   `json:"distributed_public_key"`
	PubShares           []ethHex `json:"public_shares,omitempty"`
	FeeRecipientAddress ethHex   `json:"fee_recipient_address,omitempty"`
}

// distValidatorJSONv1x6 is the json formatter of DistValidator for versions v1.6.0.
type distValidatorJSONv1x6 struct {
	PubKey      ethHex          `json:"distributed_public_key"`
	PubShares   []ethHex        `json:"public_shares,omitempty"`
	DepositData depositDataJSON `json:"deposit_data,omitempty"`
}

// distValidatorJSONv1x7 is the json formatter of DistValidator for versions v1.7.0 or later.
type distValidatorJSONv1x7 struct {
	PubKey              ethHex                  `json:"distributed_public_key"`
	PubShares           []ethHex                `json:"public_shares,omitempty"`
	DepositData         depositDataJSON         `json:"deposit_data,omitempty"`
	BuilderRegistration builderRegistrationJSON `json:"builder_registration,omitempty"`
}

func distValidatorsFromV1x1(distValidators []distValidatorJSONv1x1) []DistValidator {
	var resp []DistValidator
	for _, dv := range distValidators {
		resp = append(resp, DistValidator{
			PubKey:    dv.PubKey,
			PubShares: dv.PubShares,
		})
	}

	return resp
}

func distValidatorsToV1x1(distValidators []DistValidator) []distValidatorJSONv1x1 {
	var resp []distValidatorJSONv1x1
	for _, dv := range distValidators {
		resp = append(resp, distValidatorJSONv1x1{
			PubKey:    dv.PubKey,
			PubShares: dv.PubShares,
		})
	}

	return resp
}

func distValidatorsFromV1x2to5(distValidators []distValidatorJSONv1x2to5) []DistValidator {
	var resp []DistValidator
	for _, dv := range distValidators {
		var shares [][]byte
		for _, share := range dv.PubShares {
			shares = append(shares, share)
		}
		resp = append(resp, DistValidator{
			PubKey:    dv.PubKey,
			PubShares: shares,
		})
	}

	return resp
}

func distValidatorsToV1x2to5(distValidators []DistValidator) []distValidatorJSONv1x2to5 {
	var resp []distValidatorJSONv1x2to5
	for _, dv := range distValidators {
		var shares []ethHex
		for _, share := range dv.PubShares {
			shares = append(shares, share)
		}

		resp = append(resp, distValidatorJSONv1x2to5{
			PubKey:    dv.PubKey,
			PubShares: shares,
		})
	}

	return resp
}

func distValidatorsFromV1x6(distValidators []distValidatorJSONv1x6) []DistValidator {
	var resp []DistValidator
	for _, dv := range distValidators {
		var shares [][]byte
		for _, share := range dv.PubShares {
			shares = append(shares, share)
		}
		resp = append(resp, DistValidator{
			PubKey:      dv.PubKey,
			PubShares:   shares,
			DepositData: depositDataFromJSON(dv.DepositData),
		})
	}

	return resp
}

func distValidatorsToV1x6(distValidators []DistValidator) []distValidatorJSONv1x6 {
	var resp []distValidatorJSONv1x6
	for _, dv := range distValidators {
		var shares []ethHex
		for _, share := range dv.PubShares {
			shares = append(shares, share)
		}

		resp = append(resp, distValidatorJSONv1x6{
			PubKey:      dv.PubKey,
			PubShares:   shares,
			DepositData: depositDataToJSON(dv.DepositData),
		})
	}

	return resp
}

func distValidatorsToV1x7OrLater(distValidators []DistValidator) []distValidatorJSONv1x7 {
	var resp []distValidatorJSONv1x7
	for _, dv := range distValidators {
		var shares []ethHex
		for _, share := range dv.PubShares {
			shares = append(shares, share)
		}

		resp = append(resp, distValidatorJSONv1x7{
			PubKey:              dv.PubKey,
			PubShares:           shares,
			DepositData:         depositDataToJSON(dv.DepositData),
			BuilderRegistration: registrationToJSON(dv.BuilderRegistration),
		})
	}

	return resp
}

func byteSliceArrayToEthHex(data [][]byte) []ethHex {
	ret := make([]ethHex, 0, len(data))
	for _, d := range data {
		ret = append(ret, d)
	}

	return ret
}

func distValidatorsFromV1x7OrLater(distValidators []distValidatorJSONv1x7) []DistValidator {
	var resp []DistValidator
	for _, dv := range distValidators {
		var shares [][]byte
		for _, share := range dv.PubShares {
			shares = append(shares, share)
		}

		resp = append(resp, DistValidator{
			PubKey:              dv.PubKey,
			PubShares:           shares,
			DepositData:         depositDataFromJSON(dv.DepositData),
			BuilderRegistration: registrationFromJSON(dv.BuilderRegistration),
		})
	}

	return resp
}
