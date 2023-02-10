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

package cluster

import (
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
	tblsconv2 "github.com/obolnetwork/charon/tbls/v2/tblsconv"
)

// DistValidator is a distributed validator (1x32ETH) managed by the cluster.
type DistValidator struct {
	// PubKey is the distributed validator group public key.
	PubKey []byte `json:"distributed_public_key"  ssz:"Bytes48" lock_hash:"0"`

	// PubShares are the public keys corresponding to each node's secret key share.
	// It can be used to verify a partial signature created by any node in the cluster.
	PubShares [][]byte `json:"public_shares,omitempty" ssz:"CompositeList[256],Bytes48" lock_hash:"1"`
}

// PublicKey returns the validator BLS group public key.
func (v DistValidator) PublicKey() (tblsv2.PublicKey, error) {
	return tblsconv2.PubkeyFromBytes(v.PubKey)
}

// PublicKeyHex returns the validator hex group public key.
func (v DistValidator) PublicKeyHex() string {
	return to0xHex(v.PubKey)
}

// PublicShare returns a peer's threshold BLS public share.
func (v DistValidator) PublicShare(peerIdx int) (tblsv2.PublicKey, error) {
	return tblsconv2.PubkeyFromBytes(v.PubShares[peerIdx])
}

// distValidatorJSONv1x1 is the json formatter of DistValidator for versions v1.0.0 and v1.1.0.
type distValidatorJSONv1x1 struct {
	PubKey              ethHex   `json:"distributed_public_key"`
	PubShares           [][]byte `json:"public_shares,omitempty"`
	FeeRecipientAddress ethHex   `json:"fee_recipient_address,omitempty"`
}

// distValidatorJSONv1x2 is the json formatter of DistValidator for versions v1.2.0 and later.
type distValidatorJSONv1x2 struct {
	PubKey              ethHex   `json:"distributed_public_key"`
	PubShares           []ethHex `json:"public_shares,omitempty"`
	FeeRecipientAddress ethHex   `json:"fee_recipient_address,omitempty"`
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

func distValidatorsFromV1x2orLater(distValidators []distValidatorJSONv1x2) []DistValidator {
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

func distValidatorsToV1x2orLater(distValidators []DistValidator) []distValidatorJSONv1x2 {
	var resp []distValidatorJSONv1x2
	for _, dv := range distValidators {
		var shares []ethHex
		for _, share := range dv.PubShares {
			shares = append(shares, share)
		}

		resp = append(resp, distValidatorJSONv1x2{
			PubKey:    dv.PubKey,
			PubShares: shares,
		})
	}

	return resp
}
