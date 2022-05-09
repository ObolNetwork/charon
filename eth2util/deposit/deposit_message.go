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

package deposit

import (
	"encoding/hex"
	"strings"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

var (
	eth1AddressWithdrawalPrefix = byte(0x01)
	elevenZeroes                = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
)

// depositMessage contains all the basic information necessary to activate a validator. The fields are
// hashed to get the DepositMessageRoot. This root is signed and then the signature is added to DepositData.
type depositMessage struct {
	pubKey eth2p0.BLSPubKey
	amount eth2p0.Gwei

	// WithdrawalCredentials is the 0x01 withdrawal credentials. See spec:
	// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#withdrawal-credentials
	withdrawalCredentials [32]byte
}

func (d depositMessage) HashTreeRoot() ([32]byte, error) {
	b, err := ssz.HashWithDefaultHasher(d)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash deposit message")
	}

	return b, nil
}

func (d depositMessage) HashTreeRootWith(hh *ssz.Hasher) error {
	idx := hh.Index()

	// Field 0 'pubKey`
	hh.PutBytes(d.pubKey[:])

	// Field 1 'amount'
	hh.PutUint64(uint64(d.amount))

	// Field 2 'withdrawalCredentials'
	hh.PutBytes(d.withdrawalCredentials[:])

	hh.Merkleize(idx)

	return nil
}

// MessageRoot returns the hash tree root of the deposit message.
func MessageRoot(pubkey eth2p0.BLSPubKey, withdrawalAddr string) (eth2p0.Root, error) {
	creds, err := withdrawalCredsFromAddr(withdrawalAddr)
	if err != nil {
		return eth2p0.Root{}, err
	}

	depositMessage := depositMessage{
		pubKey:                pubkey,
		amount:                depositAmt,
		withdrawalCredentials: creds,
	}

	root, err := depositMessage.HashTreeRoot()
	if err != nil {
		return eth2p0.Root{}, err
	}

	return root, nil
}

// withdrawalCredsFromAddr returns the Withdrawal Credentials corresponding to a '0x01' Ethereum withdrawal address.
func withdrawalCredsFromAddr(addr string) ([32]byte, error) {
	// Check for validity of address.
	if !common.IsHexAddress(addr) {
		return [32]byte{}, errors.New("invalid withdrawal address", z.Str("address", addr))
	}

	var creds []byte

	// Append the single byte ETH1_ADDRESS_WITHDRAWAL_PREFIX as prefix.
	creds = append(creds, eth1AddressWithdrawalPrefix)

	// Append 11 bytes of 0.
	creds = append(creds, elevenZeroes...)

	addr = strings.TrimPrefix(addr, "0x")
	addrBytes, err := hex.DecodeString(addr)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "decode address")
	}

	// Finally, append 20 bytes of ethereum address.
	creds = append(creds, addrBytes...)

	var resp [32]byte
	copy(resp[:], creds)

	return resp, nil
}
