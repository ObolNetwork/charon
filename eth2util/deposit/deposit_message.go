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

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

const ETH1_ADDRESS_WITHDRAWAL_PREFIX = "01"

// WithdrawalCredentials is the 0x01 withdrawal credentials. See spec:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#withdrawal-credentials
type WithdrawalCredentials [32]byte

// depositMessage contains all the basic information necessary to activate a validator. The fields are
// hashed to get the DepositMessageRoot. This root is signed and then the signature is added to DepositData.
type depositMessage struct {
	pubKey eth2p0.BLSPubKey
	amount eth2p0.Gwei

	// WithdrawalCredentials is the 0x01 withdrawal credentials
	withdrawalCredentials WithdrawalCredentials
}

// withdrawalCredentialsFromAddr returns the WithdrawalCredentials corresponding to a '0x01' Ethereum withdrawal address.
func withdrawalCredentialsFromAddr(addr string) (WithdrawalCredentials, error) {
	// Check for validity of address.
	if !common.IsHexAddress(addr) {
		return WithdrawalCredentials{}, errors.New("invalid withdrawal address", z.Str("address", addr))
	}

	withdrawalCreds := make([]byte, 0, 32)

	prefix, err := hex.DecodeString(ETH1_ADDRESS_WITHDRAWAL_PREFIX)
	if err != nil {
		return WithdrawalCredentials{}, errors.Wrap(err, "decode prefix")
	}
	// Append the single byte ETH1_ADDRESS_WITHDRAWAL_PREFIX as prefix.
	withdrawalCreds = append(withdrawalCreds, prefix...)

	zeroes, err := hex.DecodeString("0000000000000000000000")
	if err != nil {
		return WithdrawalCredentials{}, errors.Wrap(err, "decode zero string")
	}
	// Append 11 bytes of 0.
	withdrawalCreds = append(withdrawalCreds, zeroes...)

	// Finally, append 20 bytes of ethereum address.
	withdrawalCreds = append(withdrawalCreds, addr...)

	var resp WithdrawalCredentials
	copy(resp[:], withdrawalCreds)

	return resp, nil
}

func withdrawalAddressFromCreds(credentials WithdrawalCredentials) (string, error) {
	// TODO(xenowits): refine this method
	return string(credentials[12:]), nil
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
