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
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// DistValidator is a distributed validator (1x32ETH) managed by the cluster.
type DistValidator struct {
	// PubKey is the distributed validator group public key.
	PubKey string `json:"distributed_public_key"`

	// PubShares are the public keys corresponding to each node's secret key share.
	// It can be used to verify a partial signature created by any node in the cluster.
	PubShares [][]byte `json:"public_shares,omitempty"`

	// FeeRecipientAddress Ethereum address override for this validator, defaults to definition withdrawal address.
	FeeRecipientAddress string `json:"fee_recipient_address,omitempty"`
}

// HashTreeRoot ssz hashes the Lock object.
func (v DistValidator) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(v) //nolint:wrapcheck
}

// HashTreeRootWith ssz hashes the Lock object with a hasher.
func (v DistValidator) HashTreeRootWith(hh *ssz.Hasher) error {
	indx := hh.Index()

	// Field (0) 'PubKey'
	hh.PutBytes([]byte(v.PubKey))

	// Field (1) 'Pubshares'
	{
		subIndx := hh.Index()
		num := uint64(len(v.PubShares))
		for _, pubshare := range v.PubShares {
			hh.PutBytes(pubshare)
		}
		hh.MerkleizeWithMixin(subIndx, num, num)
	}

	// Field (2) 'FeeRecipientAddress'
	hh.PutBytes([]byte(v.FeeRecipientAddress))

	hh.Merkleize(indx)

	return nil
}

// PublicKey returns the validator group public key.
func (v DistValidator) PublicKey() (*bls_sig.PublicKey, error) {
	return tblsconv.KeyFromCore(core.PubKey(v.PubKey))
}

// PublicShare returns a peer's threshold BLS public share.
func (v DistValidator) PublicShare(peerIdx int) (*bls_sig.PublicKey, error) {
	return tblsconv.KeyFromBytes(v.PubShares[peerIdx])
}

// distValidatorJSONv1x1 is the json formatter of DistValidator for versions v1.0.0 and v1.1.0.
type distValidatorJSONv1x1 struct {
	PubKey              string   `json:"distributed_public_key"`
	PubShares           [][]byte `json:"public_shares,omitempty"`
	FeeRecipientAddress string   `json:"fee_recipient_address,omitempty"`
}

// distValidatorJSONv1x2 is the json formatter of DistValidator for versions v1.2.0 and later.
type distValidatorJSONv1x2 struct {
	PubKey              ethHex   `json:"distributed_public_key"`
	PubShares           []ethHex `json:"public_shares,omitempty"`
	FeeRecipientAddress string   `json:"fee_recipient_address,omitempty"`
}

func distValidatorsFromV1x1(distValidators []distValidatorJSONv1x1) []DistValidator {
	var resp []DistValidator
	for _, dv := range distValidators {
		var shares [][]byte
		for _, share := range dv.PubShares {
			shares = append(shares, share)
		}
		resp = append(resp, DistValidator{
			PubKey:              dv.PubKey,
			PubShares:           shares,
			FeeRecipientAddress: dv.FeeRecipientAddress,
		})
	}

	return resp
}

func distValidatorsToV1x1(distValidators []DistValidator) ([]distValidatorJSONv1x1, error) {
	var resp []distValidatorJSONv1x1
	for _, dv := range distValidators {
		var shares []ethHex
		for _, share := range dv.PubShares {
			shares = append(shares, share)
		}
		resp = append(resp, distValidatorJSONv1x1{
			PubKey:              dv.PubKey,
			PubShares:           dv.PubShares,
			FeeRecipientAddress: dv.FeeRecipientAddress,
		})
	}

	return resp, nil
}

func distValidatorsFromV1x2(distValidators []distValidatorJSONv1x2) []DistValidator {
	var resp []DistValidator
	for _, dv := range distValidators {
		var shares [][]byte
		for _, share := range dv.PubShares {
			shares = append(shares, share)
		}
		resp = append(resp, DistValidator{
			PubKey:              fmt.Sprintf("%#x", dv.PubKey),
			PubShares:           shares,
			FeeRecipientAddress: dv.FeeRecipientAddress,
		})
	}

	return resp
}

func distValidatorsToV1x2(distValidators []DistValidator) ([]distValidatorJSONv1x2, error) {
	var resp []distValidatorJSONv1x2
	for _, dv := range distValidators {
		var shares []ethHex
		for _, share := range dv.PubShares {
			shares = append(shares, share)
		}

		pk, err := hex.DecodeString(strings.TrimPrefix(dv.PubKey, "0x"))
		if err != nil {
			return nil, errors.Wrap(err, "decode pubkey")
		}
		resp = append(resp, distValidatorJSONv1x2{
			PubKey:              pk,
			PubShares:           shares,
			FeeRecipientAddress: dv.FeeRecipientAddress,
		})
	}

	return resp, nil
}
