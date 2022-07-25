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
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	b58 "github.com/mr-tron/base58"

	"github.com/obolnetwork/charon/app/errors"
)

// uuid returns a random uuid.
func uuid(random io.Reader) string {
	b := make([]byte, 16)
	_, _ = random.Read(b)

	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
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
	signerData := apitypes.TypedData{
		Types: apitypes.Types{
			"Challenge": []apitypes.Type{
				{Name: "address", Type: "address"},
				{Name: "nonce", Type: "uint256"},
				{Name: "message", Type: "bytes"},
			},
			"EIP712Domain": []apitypes.Type{
				{Name: "name", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "version", Type: "string"},
				{Name: "salt", Type: "string"},
			},
		},
		PrimaryType: "Challenge",
		Domain: apitypes.TypedDataDomain{
			Name:    "ETHChallenger",
			Version: "1",
			Salt:    "charon_salt",              // Fixed for now.
			ChainId: math.NewHexOrDecimal256(1), // Fixed for now.
		},
		Message: apitypes.TypedDataMessage{
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

// base58 represents a byte slices that is json formatted as base58.
type base58 []byte

func (b *base58) UnmarshalJSON(data []byte) error {
	var str58 string
	if err := json.Unmarshal(data, &str58); err != nil {
		return errors.Wrap(err, "unmarshal base58 string")
	}

	resp, err := b58.Decode(str58)
	if err != nil {
		return errors.Wrap(err, "unmarshal base58")
	}

	*b = resp

	return nil
}

func (b base58) MarshalJSON() ([]byte, error) {
	resp, err := json.Marshal(b58.Encode(b))
	if err != nil {
		return nil, errors.Wrap(err, "marshal base58")
	}

	return resp, nil
}

// ethHex represents a byte slices that is json formatted as 0x prefixed hex.
type ethHex []byte

func (h *ethHex) UnmarshalJSON(data []byte) error {
	var strHex string
	if err := json.Unmarshal(data, &strHex); err != nil {
		return errors.Wrap(err, "unmarshal hex string")
	}

	resp, err := hex.DecodeString(strings.TrimPrefix(strHex, "0x"))
	if err != nil {
		return errors.Wrap(err, "unmarshal hex")
	}

	*h = resp

	return nil
}

func (h ethHex) MarshalJSON() ([]byte, error) {
	resp, err := json.Marshal(fmt.Sprintf("%#x", h))
	if err != nil {
		return nil, errors.Wrap(err, "marshal hex")
	}

	return resp, nil
}
