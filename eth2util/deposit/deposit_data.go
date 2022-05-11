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
	"encoding/json"
	"fmt"
	"strings"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

var (
	// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#eth1_address_withdrawal_prefix
	eth1AddressWithdrawalPrefix = byte(0x01)

	// the amount of ether in gwei required to activate a validator.
	validatorAmt uint64 = 32000000000

	// zeroes11 refers to a zeroed out 11 byte array.
	zeroBytes11 = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	// zeroes refers to a zeroed out 32 byte array.
	zeroBytes32 = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	// DOMAIN_DEPOSIT. See spec: https://benjaminion.xyz/eth2-annotated-spec/phase0/beacon-chain/#domain-types
	depositDomainType = []byte{0x03, 0x00, 0x00, 0x00}
)

// GetMessageRoot returns both the hash root and the signing root of the deposit message.
func GetMessageRoot(pubkey eth2p0.BLSPubKey, withdrawalCreds [32]byte, forkVersion eth2p0.Version) (eth2p0.Root, eth2p0.Root, error) {
	dm := eth2p0.DepositMessage{
		PublicKey:             pubkey,
		WithdrawalCredentials: withdrawalCreds[:],
		Amount:                eth2p0.Gwei(validatorAmt),
	}

	hashRoot, err := dm.HashTreeRoot()
	if err != nil {
		return eth2p0.Root{}, eth2p0.Root{}, errors.Wrap(err, "deposit message hash root")
	}

	signingRoot, err := GetSigningRoot(forkVersion, hashRoot)
	if err != nil {
		return eth2p0.Root{}, eth2p0.Root{}, errors.Wrap(err, "deposit message root")
	}

	return hashRoot, signingRoot, nil
}

// GetDataRoot returns both the hash root and the signing root of the deposit data.
func GetDataRoot(pubkey eth2p0.BLSPubKey, withdrawalCreds [32]byte, sig eth2p0.BLSSignature, forkVersion eth2p0.Version) (eth2p0.Root, eth2p0.Root, error) {
	dd := eth2p0.DepositData{
		PublicKey:             pubkey,
		WithdrawalCredentials: withdrawalCreds[:],
		Amount:                eth2p0.Gwei(validatorAmt),
		Signature:             sig,
	}

	hashRoot, err := dd.HashTreeRoot()
	if err != nil {
		return eth2p0.Root{}, eth2p0.Root{}, errors.Wrap(err, "deposit data hash root")
	}

	// calculate depositData root
	signingRoot, err := GetSigningRoot(forkVersion, hashRoot)
	if err != nil {
		return eth2p0.Root{}, eth2p0.Root{}, errors.Wrap(err, "deposit data root")
	}

	return hashRoot, signingRoot, nil
}

// NewDepositData returns the json serialized DepositData.
func NewDepositData(pubkey eth2p0.BLSPubKey, withdrawalAddr string, sig eth2p0.BLSSignature, network string) ([]byte, error) {
	forkVersion := networkToForkVersion(network)

	creds, err := withdrawalCredsFromAddr(withdrawalAddr)
	if err != nil {
		return nil, errors.Wrap(err, "withdrawal credentials")
	}

	// calculate depositMessage root
	dmHashRoot, _, err := GetMessageRoot(pubkey, creds, forkVersion)
	if err != nil {
		return nil, errors.Wrap(err, "deposit message root")
	}

	// calculate depositData root
	ddHashRoot, _, err := GetDataRoot(pubkey, creds, sig, forkVersion)
	if err != nil {
		return nil, errors.Wrap(err, "deposit data root")
	}

	bytes, err := json.MarshalIndent(&ddJSON{
		PubKey:                fmt.Sprintf("%x", pubkey),
		WithdrawalCredentials: fmt.Sprintf("%x", creds),
		Amount:                validatorAmt,
		Signature:             fmt.Sprintf("%x", sig),
		DepositMessageRoot:    fmt.Sprintf("%x", dmHashRoot),
		DepositDataRoot:       fmt.Sprintf("%x", ddHashRoot),
		ForkVersion:           fmt.Sprintf("%x", forkVersion),
		NetworkName:           network,
	}, "", " ")
	if err != nil {
		return nil, errors.Wrap(err, "marshal deposit data json")
	}

	return bytes, nil
}

// GetDomain returns the Signature Domain.
func GetDomain(forkVersion eth2p0.Version, domainType eth2p0.DomainType) (eth2p0.Domain, error) {
	// For deposit, genesisValidatorsRoot is a fixed value.
	var genesisValidatorsRoot eth2p0.Root
	copy(genesisValidatorsRoot[:], zeroBytes32)

	forkData := &eth2p0.ForkData{
		CurrentVersion:        forkVersion,
		GenesisValidatorsRoot: genesisValidatorsRoot,
	}
	root, err := forkData.HashTreeRoot()
	if err != nil {
		return eth2p0.Domain{}, errors.Wrap(err, "failed to calculate signature domain")
	}

	var domain eth2p0.Domain
	copy(domain[:], domainType[:])
	copy(domain[4:], root[:])

	return domain, nil
}

// GetSigningRoot returns the signing root by combining a hash root with the deposit domain.
func GetSigningRoot(forkVersion eth2p0.Version, root eth2p0.Root) ([32]byte, error) {
	var domainType eth2p0.DomainType
	copy(domainType[:], depositDomainType)

	domain, err := GetDomain(forkVersion, domainType)
	if err != nil {
		return [32]byte{}, err
	}

	msg, err := (&eth2p0.SigningData{ObjectRoot: root, Domain: domain}).HashTreeRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "signing data root")
	}

	return msg, nil
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
	creds = append(creds, zeroBytes11...)

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

// networkToForkVersion returns the fork version corresponding to a given network. If no known network found,
// simply returns the mainnet fork version.
func networkToForkVersion(network string) eth2p0.Version {
	var fvBytes []byte

	switch network {
	case "mainnet":
		fvBytes = []byte{0x00, 0x00, 0x00, 0x00}
	case "prater":
		fvBytes = []byte{0x00, 0x00, 0x10, 0x20}
	case "kintsugi":
		fvBytes = []byte{0x60, 0x00, 0x00, 0x69}
	case "kiln":
		fvBytes = []byte{0x70, 0x00, 0x00, 0x69}
	case "gnosis":
		fvBytes = []byte{0x00, 0x00, 0x00, 0x64}
	default:
		fvBytes = []byte{0x00, 0x00, 0x00, 0x00}
	}

	var forkVersion eth2p0.Version
	copy(forkVersion[:], fvBytes)

	return forkVersion
}

// ddJSON is the json formatter for depositData.
type ddJSON struct {
	PubKey                string `json:"pubkey"`
	WithdrawalCredentials string `json:"withdrawal_credentials"`
	Amount                uint64 `json:"amount"`
	Signature             string `json:"signature"`
	DepositMessageRoot    string `json:"deposit_message_root"`
	DepositDataRoot       string `json:"deposit_data_root"`
	ForkVersion           string `json:"fork_version"`
	NetworkName           string `json:"network_name"`
}
