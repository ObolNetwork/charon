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
	"bytes"
	"encoding/json"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
)

// DepositData contains all the information required for activating validators on the Ethereum Network.
type DepositData struct {
	// PubKey is the group public key for a Distributed Validator.
	PubKey eth2p0.BLSPubKey

	// Amount is the amount of Eth needed to activate a validator.
	Amount eth2p0.Gwei

	// Eth1WithdrawalAddress is the Ethereum withdrawal address.
	Eth1WithdrawalAddress string

	// DepositMessageRoot is the hash tree root of DepositMessage.
	DepositMessageRoot eth2p0.Root

	// Signature is constructed from DepositMessageRoot combined with DOMAIN_DEPOSIT.
	Signature eth2p0.BLSSignature

	// ForkVersion identifies the network/chainID.
	ForkVersion eth2p0.Version
}

// GenerateDepositData generates a deposit data object by populating the required fields.
func GenerateDepositData(addr string, forkVersion string, pubkey eth2p0.BLSPubKey) (DepositData, error) {
	amount := eth2p0.Gwei(32000000000)
	withdrawalCreds, err := withdrawalCredentialsFromAddr(addr)
	if err != nil {
		return DepositData{}, err
	}

	depositMessage := depositMessage{
		pubKey:                pubkey,
		amount:                amount,
		withdrawalCredentials: withdrawalCreds,
	}

	// calculate the hash tree root of depositMessage
	depositMessageRoot, err := depositMessage.HashTreeRoot()
	if err != nil {
		return DepositData{}, err
	}

	// TODO(xenowits): sign depositMsgRoot. Note that this is done in a distributed environment.
	signature := eth2p0.BLSSignature{}

	var version eth2p0.Version
	copy(version[:], forkVersion)

	depositData := DepositData{
		PubKey:                pubkey,
		Amount:                amount,
		Eth1WithdrawalAddress: addr,
		DepositMessageRoot:    depositMessageRoot,
		Signature:             signature,
		ForkVersion:           version,
	}

	return depositData, nil
}

// forkVersionToNetwork returns the name of the ethereum network corresponding to a given fork version.
func forkVersionToNetwork(forkVersion string) string {
	switch forkVersion {
	case "00000000":
		return "mainnet"
	case "00001020":
		return "prater"
	case "60000069":
		return "kintsugi"
	case "70000069":
		return "kiln"
	case "00000064":
		return "gnosis"
	default:
		return "mainnet"
	}
}

func (d DepositData) HashTreeRoot() ([32]byte, error) {
	b, err := ssz.HashWithDefaultHasher(d)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash deposit data")
	}

	return b, nil
}

func (d DepositData) HashTreeRootWith(hh *ssz.Hasher) error {
	idx := hh.Index()

	// Field 0 'PubKey`
	hh.PutBytes(d.PubKey[:])

	// Field 1 'Amount'
	hh.PutUint64(uint64(d.Amount))

	// Field 2 'Eth1WithdrawalAddress'
	hh.PutBytes([]byte(d.Eth1WithdrawalAddress))

	// Field 3 'DepositMessageRoot'
	hh.PutBytes(d.DepositMessageRoot[:])

	// Field 4 'Signature'
	hh.PutBytes(d.Signature[:])

	// Field 5 'ForkVersion'
	hh.PutBytes(d.ForkVersion[:])

	hh.Merkleize(idx)

	return nil
}

func (d DepositData) MarshalJSON() ([]byte, error) {
	// Marshal definition hash
	hash, err := d.HashTreeRoot()
	if err != nil {
		return nil, errors.Wrap(err, "hash deposit data")
	}

	creds, err := withdrawalCredentialsFromAddr(d.Eth1WithdrawalAddress)
	if err != nil {
		return nil, err
	}

	// Marshal json version of deposit data
	resp, err := json.Marshal(ddFmt{
		PubKey:                d.PubKey[:],
		Amount:                uint64(d.Amount),
		WithdrawalCredentials: creds[:],
		DepositDataRoot:       hash[:],
		DepositMessageRoot:    d.DepositMessageRoot[:],
		Signature:             d.Signature[:],
		ForkVersion:           d.ForkVersion[:],
		NetworkName:           forkVersionToNetwork(string(d.ForkVersion[:])),
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal deposit data")
	}

	return resp, nil
}

func (d *DepositData) UnmarshalJSON(data []byte) error {
	var ddFmt ddFmt
	if err := json.Unmarshal(data, &ddFmt); err != nil {
		return errors.Wrap(err, "unmarshal deposit data")
	}

	var pubkey eth2p0.BLSPubKey
	copy(pubkey[:], ddFmt.PubKey)

	var depositMessageRoot eth2p0.Root
	copy(depositMessageRoot[:], ddFmt.DepositMessageRoot)

	var signature eth2p0.BLSSignature
	copy(signature[:], ddFmt.Signature)

	var forkVersion eth2p0.Version
	copy(forkVersion[:], ddFmt.ForkVersion)

	var withdrawalCreds WithdrawalCredentials
	copy(withdrawalCreds[:], ddFmt.WithdrawalCredentials)

	withdrawalAddr, err := withdrawalAddressFromCreds(withdrawalCreds)
	if err != nil {
		return err
	}

	dd := DepositData{
		PubKey:                pubkey,
		Amount:                eth2p0.Gwei(ddFmt.Amount),
		Eth1WithdrawalAddress: withdrawalAddr,
		DepositMessageRoot:    depositMessageRoot,
		Signature:             signature,
		ForkVersion:           forkVersion,
	}

	hash, err := dd.HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "hash deposit data")
	}

	if !bytes.Equal(ddFmt.DepositDataRoot, hash[:]) {
		return errors.New("invalid deposit data hash")
	}

	*d = dd

	return nil
}

// ddFmt is the json formatter for DepositData.
type ddFmt struct {
	PubKey                []byte `json:"pubkey"`
	Amount                uint64 `json:"amount"`
	WithdrawalCredentials []byte `json:"withdrawal_credentials"`
	DepositDataRoot       []byte `json:"deposit_data_root"`
	DepositMessageRoot    []byte `json:"deposit_message_root"`
	Signature             []byte `json:"signature"`
	ForkVersion           []byte `json:"fork_version"`
	NetworkName           string `json:"network_name"`
}
