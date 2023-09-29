// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package deposit provides functions to create deposit data files.
package deposit

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/tbls"
)

var (
	// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#eth1_address_withdrawal_prefix
	eth1AddressWithdrawalPrefix = []byte{0x01}

	// the amount of ether in gwei required to activate a validator.
	validatorAmt = eth2p0.Gwei(32000000000)

	// DOMAIN_DEPOSIT. See spec: https://benjaminion.xyz/eth2-annotated-spec/phase0/beacon-chain/#domain-types
	depositDomainType = eth2p0.DomainType([4]byte{0x03, 0x00, 0x00, 0x00})

	depositCliVersion = "2.7.0"
)

// NewMessage returns a deposit message created using the provided parameters.
func NewMessage(pubkey eth2p0.BLSPubKey, withdrawalAddr string) (eth2p0.DepositMessage, error) {
	creds, err := withdrawalCredsFromAddr(withdrawalAddr)
	if err != nil {
		return eth2p0.DepositMessage{}, err
	}

	return eth2p0.DepositMessage{
		PublicKey:             pubkey,
		WithdrawalCredentials: creds[:],
		Amount:                validatorAmt,
	}, nil
}

// MarshalDepositData serializes a list of deposit data into a single file.
func MarshalDepositData(depositDatas []eth2p0.DepositData, network string) ([]byte, error) {
	forkVersion, err := eth2util.NetworkToForkVersion(network)
	if err != nil {
		return nil, err
	}

	var ddList []depositDataJSON
	for _, depositData := range depositDatas {
		msg := eth2p0.DepositMessage{
			PublicKey:             depositData.PublicKey,
			WithdrawalCredentials: depositData.WithdrawalCredentials,
			Amount:                depositData.Amount,
		}
		msgRoot, err := msg.HashTreeRoot()
		if err != nil {
			return nil, err
		}

		// Verify deposit data signature
		sigData, err := GetMessageSigningRoot(msg, network)
		if err != nil {
			return nil, err
		}

		blsSig := tbls.Signature(depositData.Signature)
		blsPubkey := tbls.PublicKey(depositData.PublicKey)

		err = tbls.Verify(blsPubkey, sigData[:], blsSig)
		if err != nil {
			return nil, errors.Wrap(err, "invalid deposit data signature")
		}

		dataRoot, err := depositData.HashTreeRoot()
		if err != nil {
			return nil, errors.Wrap(err, "deposit data hash root")
		}

		ddList = append(ddList, depositDataJSON{
			PubKey:                fmt.Sprintf("%x", depositData.PublicKey),
			WithdrawalCredentials: fmt.Sprintf("%x", depositData.WithdrawalCredentials),
			Amount:                uint64(validatorAmt),
			Signature:             fmt.Sprintf("%x", depositData.Signature),
			DepositMessageRoot:    fmt.Sprintf("%x", msgRoot),
			DepositDataRoot:       fmt.Sprintf("%x", dataRoot),
			ForkVersion:           strings.TrimPrefix(forkVersion, "0x"),
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
func GetMessageSigningRoot(msg eth2p0.DepositMessage, network string) ([32]byte, error) {
	msgRoot, err := msg.HashTreeRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "deposit message root")
	}

	fv, err := eth2util.NetworkToForkVersionBytes(network)
	if err != nil {
		return [32]byte{}, err
	}

	var forkVersion eth2p0.Version
	copy(forkVersion[:], fv)

	domain, err := getDepositDomain(forkVersion)
	if err != nil {
		return [32]byte{}, err
	}

	resp, err := (&eth2p0.SigningData{ObjectRoot: msgRoot, Domain: domain}).HashTreeRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "signing data root")
	}

	return resp, nil
}

// withdrawalCredsFromAddr returns the Withdrawal Credentials corresponding to a '0x01' Ethereum withdrawal address.
func withdrawalCredsFromAddr(addr string) ([32]byte, error) {
	// Check for validity of address.
	if _, err := eth2util.ChecksumAddress(addr); err != nil {
		return [32]byte{}, errors.Wrap(err, "invalid withdrawal address", z.Str("addr", addr))
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
