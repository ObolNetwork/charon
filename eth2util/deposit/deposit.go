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

// Package deposit provides functions to create deposit data files.
package deposit

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

var (
	// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#eth1_address_withdrawal_prefix
	eth1AddressWithdrawalPrefix = []byte{0x01}

	// the amount of ether in gwei required to activate a validator.
	validatorAmt = eth2p0.Gwei(32000000000)

	// DOMAIN_DEPOSIT. See spec: https://benjaminion.xyz/eth2-annotated-spec/phase0/beacon-chain/#domain-types
	depositDomainType = eth2p0.DomainType([4]byte{0x03, 0x00, 0x00, 0x00})

	depositCliVersion = "2.3.0"
)

// getMessageRoot returns a deposit message hash root created by the parameters.
func getMessageRoot(pubkey eth2p0.BLSPubKey, withdrawalAddr string) (eth2p0.Root, error) {
	creds, err := withdrawalCredsFromAddr(withdrawalAddr)
	if err != nil {
		return eth2p0.Root{}, err
	}

	dm := eth2p0.DepositMessage{
		PublicKey:             pubkey,
		WithdrawalCredentials: creds[:],
		Amount:                validatorAmt,
	}
	hashRoot, err := dm.HashTreeRoot()
	if err != nil {
		return eth2p0.Root{}, errors.Wrap(err, "deposit message hash root")
	}

	return hashRoot, nil
}

// MarshalDepositData serializes a list of deposit data into a single file.
func MarshalDepositData(msgSigs map[eth2p0.BLSPubKey]eth2p0.BLSSignature, withdrawalAddr, network string) ([]byte, error) {
	creds, err := withdrawalCredsFromAddr(withdrawalAddr)
	if err != nil {
		return nil, err
	}

	forkVersion := networkToForkVersion(network)

	var ddList []depositDataJSON
	for pubkey, sig := range msgSigs {
		// calculate depositMessage root
		msgRoot, err := getMessageRoot(pubkey, withdrawalAddr)
		if err != nil {
			return nil, err
		}

		// Verify deposit data signature
		sigData, err := GetMessageSigningRoot(pubkey, withdrawalAddr, network)
		if err != nil {
			return nil, err
		}

		blsSig, err := tblsconv.SigFromETH2(sig)
		if err != nil {
			return nil, err
		}
		blsPubkey, err := tblsconv.KeyFromETH2(pubkey)
		if err != nil {
			return nil, err
		}

		ok, err := tbls.Verify(blsPubkey, sigData[:], blsSig)
		if err != nil {
			return nil, err
		} else if !ok {
			return nil, errors.New("invalid deposit data signature")
		}

		dd := eth2p0.DepositData{
			PublicKey:             pubkey,
			WithdrawalCredentials: creds[:],
			Amount:                validatorAmt,
			Signature:             sig,
		}
		dataRoot, err := dd.HashTreeRoot()
		if err != nil {
			return nil, errors.Wrap(err, "deposit data hash root")
		}

		ddList = append(ddList, depositDataJSON{
			PubKey:                fmt.Sprintf("%x", pubkey),
			WithdrawalCredentials: fmt.Sprintf("%x", creds),
			Amount:                uint64(validatorAmt),
			Signature:             fmt.Sprintf("%x", sig),
			DepositMessageRoot:    fmt.Sprintf("%x", msgRoot),
			DepositDataRoot:       fmt.Sprintf("%x", dataRoot),
			ForkVersion:           fmt.Sprintf("%x", forkVersion),
			NetworkName:           network,
			DepositCliVersion:     depositCliVersion,
		})
	}

	sort.Slice(ddList, func(i, j int) bool {
		return ddList[i].PubKey < ddList[j].PubKey
	})

	bytes, err := json.MarshalIndent(ddList, "", " ")
	if err != nil {
		return nil, errors.Wrap(err, "marshal deposit data")
	}

	return bytes, nil
}

// getDepositDomain returns the deposit signature domain.
func getDepositDomain(forkVersion eth2p0.Version) (eth2p0.Domain, error) {
	forkData := &eth2p0.ForkData{
		CurrentVersion:        forkVersion,
		GenesisValidatorsRoot: eth2p0.Root{}, // GenesisValidatorsRoot is zero for deposit domain.
	}
	root, err := forkData.HashTreeRoot()
	if err != nil {
		return eth2p0.Domain{}, errors.Wrap(err, "hash fork data")
	}

	var domain eth2p0.Domain
	copy(domain[0:], depositDomainType[:])
	copy(domain[4:], root[:])

	return domain, nil
}

// GetMessageSigningRoot returns the deposit message signing root created by the provided parameters.
func GetMessageSigningRoot(pubkey eth2p0.BLSPubKey, withdrawalAddr string, network string) ([32]byte, error) {
	msgRoot, err := getMessageRoot(pubkey, withdrawalAddr)
	if err != nil {
		return [32]byte{}, err
	}

	domain, err := getDepositDomain(networkToForkVersion(network))
	if err != nil {
		return [32]byte{}, err
	}

	resp, err := (&eth2p0.SigningData{ObjectRoot: msgRoot, Domain: domain}).HashTreeRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "signing data root")
	}

	return resp, nil
}

// WithdrawalCredsFromAddr returns the Withdrawal Credentials corresponding to a '0x01' Ethereum withdrawal address.
func withdrawalCredsFromAddr(addr string) ([32]byte, error) {
	// Check for validity of address.
	if !common.IsHexAddress(addr) {
		return [32]byte{}, errors.New("invalid withdrawal address", z.Str("address", addr))
	}

	addrBytes, err := hex.DecodeString(strings.TrimPrefix(addr, "0x"))
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "decode address")
	}

	var creds [32]byte
	copy(creds[0:], eth1AddressWithdrawalPrefix) // Add 1 byte prefix.
	copy(creds[12:], addrBytes)                  // Add 20 bytes of ethereum address suffix.

	return creds, nil
}

// networkToForkVersion returns the fork version corresponding to a given network. If no known network found,
// simply returns the mainnet fork version.
func networkToForkVersion(network string) eth2p0.Version {
	switch network {
	case "prater":
		return [4]byte{0x00, 0x00, 0x10, 0x20}
	case "kiln":
		return [4]byte{0x70, 0x00, 0x00, 0x69}
	case "ropsten":
		return [4]byte{0x80, 0x00, 0x00, 0x69}
	case "gnosis":
		return [4]byte{0x00, 0x00, 0x00, 0x64}
	case "mainnet": // Default to mainnet
		fallthrough
	default:
		return [4]byte{0x00, 0x00, 0x00, 0x00}
	}
}

// depositDataJSON is the json representation of Deposit Data.
type depositDataJSON struct {
	PubKey                string `json:"pubkey"`
	WithdrawalCredentials string `json:"withdrawal_credentials"`
	Amount                uint64 `json:"amount"`
	Signature             string `json:"signature"`
	DepositMessageRoot    string `json:"deposit_message_root"`
	DepositDataRoot       string `json:"deposit_data_root"`
	ForkVersion           string `json:"fork_version"`
	NetworkName           string `json:"network_name"`
	DepositCliVersion     string `json:"deposit_cli_version"`
}
