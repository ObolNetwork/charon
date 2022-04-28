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
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	signtypes "github.com/ethereum/go-ethereum/signer/core/apitypes"

	"github.com/obolnetwork/charon/app/errors"
)

// Sealed returns true of all operator signatures are populated and valid.
func (p Params) Sealed() (bool, error) {
	paramHash, err := p.HashTreeRoot()
	if err != nil {
		return false, errors.Wrap(err, "param hash")
	}

	// Check that we a operator signature for each operator.
	for _, o := range p.Operators {
		digest, err := digestEIP712(o.Address, paramHash[:], 0)
		if err != nil {
			return false, err
		}

		var found bool
		for _, sig := range p.OperatorSignatures {
			if ok, err := verifySig(o.Address, digest[:], sig); err != nil {
				return false, err
			} else if ok {
				found = true
				break
			}
		}

		if !found {
			return false, nil
		}
	}

	// TODO(corver): Also validate all operator sigs are valid

	return true, nil
}

// VerifySignature returns an error if the ENR signature doesn't match the address and enr fields.
func (o Operator) VerifySignature() error {
	digest, err := digestEIP712(o.Address, []byte(o.ENR), o.Nonce)
	if err != nil {
		return err
	}

	if ok, err := verifySig(o.Address, digest[:], o.ENRSignature); err != nil {
		return err
	} else if !ok {
		return errors.New("invalid operator enr signature")
	}

	return nil
}

// verifySig returns true if the signature matches the digest and address.
func verifySig(addr string, digest []byte, sig []byte) (bool, error) {
	pubkey, err := crypto.SigToPub(digest, sig)
	if err != nil {
		return false, errors.Wrap(err, "pubkey from signature")
	}

	expect := crypto.PubkeyToAddress(*pubkey).String()
	actual := addr

	expect = strings.ToLower(strings.TrimPrefix(expect, "0x"))
	actual = strings.ToLower(strings.TrimPrefix(actual, "0x"))

	return actual == expect, nil
}

// digestEIP712 returns EIP712 digest hash.
// See reference https://medium.com/alpineintel/issuing-and-verifying-eip-712-challenges-with-go-32635ca78aaf.
func digestEIP712(address string, message []byte, nonce int) ([32]byte, error) {
	signerData := signtypes.TypedData{
		Types: signtypes.Types{
			"Challenge": []signtypes.Type{
				{Name: "address", Type: "address"},
				{Name: "nonce", Type: "uint256"},
				{Name: "message", Type: "bytes"},
			},
			"EIP712Domain": []signtypes.Type{
				{Name: "name", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "version", Type: "string"},
				{Name: "salt", Type: "string"},
			},
		},
		PrimaryType: "Challenge",
		Domain: signtypes.TypedDataDomain{
			Name:    "ETHChallenger",
			Version: "1",
			Salt:    "charon_salt",              // Fixed for now.
			ChainId: math.NewHexOrDecimal256(1), // Fixed for now.
		},
		Message: signtypes.TypedDataMessage{
			"address": address,
			"nonce":   math.NewHexOrDecimal256(int64(nonce)),
			"message": message,
		},
	}

	typedDataHash, err := signerData.HashStruct(signerData.PrimaryType, signerData.Message)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash message")
	}
	domainSeparator, err := signerData.HashStruct("EIP712Domain", signerData.Domain.Map())
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash domain")
	}

	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))

	return crypto.Keccak256Hash(rawData), nil
}
