// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/tbls"
)

// FetchDefinition fetches cluster definition file from a remote URI.
func FetchDefinition(ctx context.Context, url string) (Definition, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Definition{}, errors.Wrap(err, "create http request")
	}

	resp, err := new(http.Client).Do(req)
	if err != nil {
		return Definition{}, errors.Wrap(err, "fetch file")
	}

	if resp.StatusCode/100 != 2 {
		return Definition{}, errors.New("http error", z.Int("status_code", resp.StatusCode))
	}

	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return Definition{}, errors.Wrap(err, "read response body")
	}

	var res Definition
	if err := json.Unmarshal(buf, &res); err != nil {
		return Definition{}, errors.Wrap(err, "unmarshal definition")
	}

	return res, nil
}

// CreateValidatorKeysDir creates a new directory for validator keys.
// If the directory "validator_keys" exists, it checks if the directory
// is empty.
func CreateValidatorKeysDir(parentDir string) (string, error) {
	vkdir := path.Join(parentDir, "validator_keys")
	err := os.Mkdir(vkdir, os.ModePerm)
	if err == nil {
		return vkdir, nil
	}
	if !os.IsExist(err) {
		return "", errors.Wrap(err, "mkdir", z.Str("path", vkdir))
	}
	files, err := os.ReadDir(vkdir)
	if err != nil {
		return "", errors.Wrap(err, "readdir", z.Str("path", vkdir))
	}
	if len(files) == 0 {
		return vkdir, nil
	}

	return "", errors.New("directory not empty", z.Str("path", vkdir))
}

// uuid returns a random uuid.
func uuid(random io.Reader) string {
	b := make([]byte, 16)
	_, _ = random.Read(b)

	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// verifySig returns true if the signature matches the digest and address.
func verifySig(expectedAddr string, digest []byte, sig []byte) (bool, error) {
	expectedAddr, err := eth2util.ChecksumAddress(expectedAddr)
	if err != nil {
		return false, err
	}

	pubkey, err := k1util.Recover(digest, sig)
	if err != nil {
		return false, errors.Wrap(err, "pubkey from signature")
	}

	actualAddr := eth2util.PublicKeyToAddress(pubkey)

	return expectedAddr == actualAddr, nil
}

// signCreator returns the definition with signed creator config hash.
func signCreator(secret *k1.PrivateKey, def Definition) (Definition, error) {
	var err error

	def.Creator.ConfigSignature, err = signEIP712(secret, eip712CreatorConfigHash, def, Operator{})
	if err != nil {
		return Definition{}, err
	}

	return def, nil
}

// signOperator returns the operator with signed config hash and enr.
func signOperator(secret *k1.PrivateKey, def Definition, operator Operator) (Operator, error) {
	var err error

	operator.ConfigSignature, err = signEIP712(secret, getOperatorEIP712Type(def.Version), def, operator)
	if err != nil {
		return Operator{}, err
	}

	operator.ENRSignature, err = signEIP712(secret, eip712ENR, def, operator)
	if err != nil {
		return Operator{}, err
	}

	return operator, nil
}

// aggSign returns a bls aggregate signatures of the message signed by all the shares.
func aggSign(secrets [][]tbls.PrivateKey, message []byte) ([]byte, error) {
	var sigs []tbls.Signature
	for _, shares := range secrets {
		for _, share := range shares {
			sig, err := tbls.Sign(share, message)
			if err != nil {
				return nil, err
			}

			sigs = append(sigs, sig)
		}
	}

	aggSig, err := tbls.Aggregate(sigs)
	if err != nil {
		return nil, errors.Wrap(err, "aggregate signatures")
	}

	return aggSig[:], nil
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
	h.AppendBytes32(b)
	h.MerkleizeWithMixin(elemIndx, uint64(byteLen), uint64(limit+31)/32)

	return nil
}

// putByteList appends b as a ssz fixed size byte array of length n.
func putBytesN(h ssz.HashWalker, b []byte, n int) error {
	if len(b) > n {
		return errors.New("bytes too long", z.Int("n", n), z.Int("l", len(b)))
	}

	h.PutBytes(leftPad(b, n))

	return nil
}

// putHexBytes20 appends a 20 byte fixed size byte ssz array from the 0xhex address.
func putHexBytes20(h ssz.HashWalker, addr string) error {
	b, err := from0xHex(addr, addressLen)
	if err != nil {
		return err
	}

	h.PutBytes(leftPad(b, addressLen))

	return nil
}

// leftPad returns the byte slice left padded with zero to ensure a length of at least l.
func leftPad(b []byte, l int) []byte {
	for len(b) < l {
		b = append([]byte{0x00}, b...)
	}

	return b
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
