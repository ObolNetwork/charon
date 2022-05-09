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
	"context"
	"encoding/hex"
	"encoding/json"
	"os"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/eth2util/signing"
)

// DepositData contains all the information required for activating validators on the Ethereum Network.
type DepositData struct { //nolint:revive
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

// SaveDepositData generates DepositData and saves it to a file.
func SaveDepositData(pubkey eth2p0.BLSPubKey, eth2Cl signing.Eth2DomainProvider, withdrawalAddr, forkVersion string) error {
	msgRoot, err := MessageRoot(pubkey, withdrawalAddr)
	if err != nil {
		return err
	}

	_, err = signing.GetDataRoot(context.Background(), eth2Cl, signing.DomainDeposit, 0, msgRoot)
	if err != nil {
		return err
	}

	// TODO(): sign the above root. This takes place in a distributed environment.
	sig := eth2p0.BLSSignature{}
	bytes, err := MarshalDepositData(pubkey, msgRoot, sig, withdrawalAddr, forkVersion)
	if err != nil {
		return err
	}

	// save bytes to disk
	depositFile := "deposit_data.json"
	err = os.WriteFile(depositFile, bytes, 0o400)
	if err != nil {
		return errors.Wrap(err, "write deposit data file")
	}

	return nil
}

// MarshalDepositData returns the json serialised deposit data bytes to be written to disk.
func MarshalDepositData(pubkey eth2p0.BLSPubKey, msgRoot eth2p0.Root, sig eth2p0.BLSSignature, withdrawalAddr, forkVersion string) ([]byte, error) {
	creds, err := withdrawalCredsFromAddr(withdrawalAddr)
	if err != nil {
		return nil, err
	}

	// construct DepositData and then calculate its hash.
	var version eth2p0.Version
	copy(version[:], forkVersion)
	d := DepositData{
		PubKey:                pubkey,
		Amount:                depositAmt,
		Eth1WithdrawalAddress: withdrawalAddr,
		DepositMessageRoot:    msgRoot,
		Signature:             sig,
		ForkVersion:           version,
	}
	hash, err := d.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	// Marshal json version of deposit data.
	resp, err := json.Marshal(ddJSON{
		PubKey:                hex.EncodeToString(pubkey[:]),
		Amount:                uint64(d.Amount),
		WithdrawalCredentials: hex.EncodeToString(creds[:]),
		DepositDataRoot:       hex.EncodeToString(hash[:]),
		DepositMessageRoot:    hex.EncodeToString(msgRoot[:]),
		Signature:             hex.EncodeToString(sig[:]),
		ForkVersion:           forkVersion,
		NetworkName:           forkVersionToNetwork(forkVersion),
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal deposit data")
	}

	return resp, nil
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

// ddJSON is the json formatter for DepositData.
type ddJSON struct {
	PubKey                string `json:"pubkey"`
	Amount                uint64 `json:"amount"`
	WithdrawalCredentials string `json:"withdrawal_credentials"`
	DepositDataRoot       string `json:"deposit_data_root"`
	DepositMessageRoot    string `json:"deposit_message_root"`
	Signature             string `json:"signature"`
	ForkVersion           string `json:"fork_version"`
	NetworkName           string `json:"network_name"`
}
