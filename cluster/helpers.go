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
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	ethmath "github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

const (
	// k1SigLen is the length of secp256k1 signatures.
	k1SigLen = 65
	// k1RecIdx is the secp256k1 signature recovery id index.
	k1RecIdx = 64

	// Fork versions.
	forkVersionMainnet = "0x00000000"
	forkVersionGoerli  = "0x00001020"
	forkVersionGnosis  = "0x00000064"
	forkVersionRopsten = "0x80000069"
	forkVersionSepolia = "0x90000069"

	// Chain IDs.
	chainIDMainnet = 1
	chainIDGoerli  = 5
	chainIDGnosis  = 100
	chainIDRopsten = 3
	chainIDSepolia = 11155111
)

// eip712Type ties the EIP712 Primary type to its Message field.
type eip712Type struct {
	PrimaryType string
	Field       string
}

var (
	eip712TypeConfigHash = eip712Type{"ConfigHash", "config_hash"}
	eip712TypeENR        = eip712Type{"ENR", "enr"}
)

// uuid returns a random uuid.
func uuid(random io.Reader) string {
	b := make([]byte, 16)
	_, _ = random.Read(b)

	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// verifySig returns true if the signature matches the digest and address.
func verifySig(expectedAddr string, digest []byte, sig []byte) (bool, error) {
	if len(sig) != k1SigLen {
		return false, errors.New("invalid signature length", z.Int("siglen", len(sig)))
	}

	// https://github.com/ethereum/go-ethereum/issues/19751#issuecomment-504900739
	// TL;DR: Metamask signatures end with 0x1b (27) or 0x1c (28) while go-ethereum/crypto signatures end with 0x0(0) or 0x1(1) and both are correct.
	if sig[k1RecIdx] != 0 && sig[k1RecIdx] != 1 && sig[k1RecIdx] != 27 && sig[k1RecIdx] != 28 {
		return false, errors.New("invalid recovery id", z.Any("id", sig[k1RecIdx]))
	}

	if sig[k1RecIdx] == 27 || sig[k1RecIdx] == 28 {
		sig[k1RecIdx] -= 27 // Make the last byte 0 or 1 since that is the canonical V value.
	}

	pubkey, err := crypto.SigToPub(digest, sig)
	if err != nil {
		return false, errors.Wrap(err, "pubkey from signature")
	}

	actualAddr := crypto.PubkeyToAddress(*pubkey)

	addrBytes, err := from0xHex(expectedAddr, addressLen)
	if err != nil {
		return false, err
	}

	return bytes.Equal(addrBytes, actualAddr[:]), nil
}

// signOperator returns the operator with signed config hash and enr.
func signOperator(secret *ecdsa.PrivateKey, operator Operator, configHash [32]byte, chainID int64) (Operator, error) {
	var err error

	operator.ConfigSignature, err = signEIP712(secret, eip712TypeConfigHash, to0xHex(configHash[:]), chainID)
	if err != nil {
		return Operator{}, err
	}

	operator.ENRSignature, err = signEIP712(secret, eip712TypeENR, operator.ENR, chainID)
	if err != nil {
		return Operator{}, err
	}

	return operator, nil
}

// signEIP712 returns the EIP712 signature for the primary type.
func signEIP712(secret *ecdsa.PrivateKey, typ eip712Type, fieldValue string, chainID int64) ([]byte, error) {
	digest, err := digestEIP712(typ, fieldValue, chainID)
	if err != nil {
		return nil, err
	}

	sig, err := crypto.Sign(digest, secret)
	if err != nil {
		return nil, errors.Wrap(err, "sign EIP712")
	}

	return sig, nil
}

// digestEIP712 returns the EIP712 (https://eips.ethereum.org/EIPS/eip-712) digest for the primary type.
func digestEIP712(typ eip712Type, fieldValue string, chainID int64) ([]byte, error) {
	data := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": []apitypes.Type{
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
			},
			typ.PrimaryType: []apitypes.Type{
				{Name: typ.Field, Type: "string"},
			},
		},
		PrimaryType: typ.PrimaryType,
		Message: apitypes.TypedDataMessage{
			typ.Field: fieldValue,
		},
		Domain: apitypes.TypedDataDomain{
			Name:    "Obol",
			Version: "1",
			ChainId: ethmath.NewHexOrDecimal256(chainID),
		},
	}

	digest, _, err := apitypes.TypedDataAndHash(data)
	if err != nil {
		return nil, errors.Wrap(err, "hash EIP712")
	}

	return digest, nil
}

// aggSign returns a bls aggregate signatures of the message signed by all the shares.
func aggSign(secrets [][]*bls_sig.SecretKeyShare, message []byte) ([]byte, error) {
	var sigs []*bls_sig.Signature
	for _, shares := range secrets {
		for _, share := range shares {
			secret, err := tblsconv.ShareToSecret(share)
			if err != nil {
				return nil, err
			}
			sig, err := tbls.Sign(secret, message)
			if err != nil {
				return nil, err
			}
			sigs = append(sigs, sig)
		}
	}

	aggSig, err := tbls.Scheme().AggregateSignatures(sigs...)
	if err != nil {
		return nil, errors.Wrap(err, "aggregate signatures")
	}

	b, err := aggSig.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "marshal signature")
	}

	return b, nil
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
	resp, err := json.Marshal(to0xHex(h))
	if err != nil {
		return nil, errors.Wrap(err, "marshal hex")
	}

	return resp, nil
}

// Threshold returns minimum threshold required for a cluster with given nodes.
// This formula has been taken from: https://github.com/ObolNetwork/charon/blob/a8fc3185bdda154412fe034dcd07c95baf5c1aaf/core/qbft/qbft.go#L63
func Threshold(nodes int) int {
	return int(math.Ceil(float64(2*nodes) / 3))
}

// putByteList appends a ssz byte list.
// See reference: github.com/attestantio/go-eth2-client/spec/bellatrix/executionpayload_encoding.go:277-284.
func putByteList(h ssz.HashWalker, b []byte, limit int, field string) error {
	elemIndx := h.Index()
	byteLen := len(b)
	if byteLen > limit {
		return errors.Wrap(ssz.ErrIncorrectListSize, "put byte list", z.Str("field", field))
	}
	h.PutBytes(b)
	h.MerkleizeWithMixin(elemIndx, uint64(byteLen), uint64(limit+31)/32)

	return nil
}

// to0xHex returns the bytes as a 0x prefixed hex string.
func to0xHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}

	return fmt.Sprintf("%#x", b)
}

// to0xHex returns bytes represented by the hex string.
func from0xHex(s string, length int) ([]byte, error) {
	if s == "" {
		return nil, nil
	}

	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return nil, errors.Wrap(err, "decode hex")
	} else if len(b) != length {
		return nil, errors.Wrap(err, "invalid hex length", z.Int("expect", length), z.Int("actual", len(b)))
	}

	return b, nil
}

// forkVersionToChainID returns the chainID corresponding to the input fork version.
func forkVersionToChainID(forkVersion []byte) (int64, error) {
	switch fmt.Sprintf("%#x", forkVersion) {
	case forkVersionMainnet:
		return chainIDMainnet, nil
	case forkVersionGoerli:
		return chainIDGoerli, nil
	case forkVersionGnosis:
		return chainIDGnosis, nil
	case forkVersionRopsten:
		return chainIDRopsten, nil
	case forkVersionSepolia:
		return chainIDSepolia, nil
	default:
		return -1, errors.New("invalid fork version")
	}
}
