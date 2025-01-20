// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package deposit provides functions to create deposit data files.
package deposit

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/tbls"
)

const (
	// 1 ETH in Gwei.
	OneEthInGwei = 1000000000
)

var (
	// Minimum allowed deposit amount (1ETH).
	MinDepositAmount = eth2p0.Gwei(1000000000)

	// Maximum allowed deposit amount (2048ETH).
	MaxDepositAmount = eth2p0.Gwei(2048000000000)

	// Default deposit amount (32ETH).
	DefaultDepositAmount = eth2p0.Gwei(32000000000)

	// https://eips.ethereum.org/EIPS/eip-7251
	eip7251AddressWithdrawalPrefix = []byte{0x02}

	// DOMAIN_DEPOSIT. See spec: https://benjaminion.xyz/eth2-annotated-spec/phase0/beacon-chain/#domain-types
	depositDomainType = eth2p0.DomainType([4]byte{0x03, 0x00, 0x00, 0x00})

	// https://github.com/ethereum/staking-deposit-cli/blob/master/staking_deposit/settings.py#L4
	depositCliVersion = "2.7.0"
)

// NewMessage returns a deposit message created using the provided parameters.
func NewMessage(pubkey eth2p0.BLSPubKey, withdrawalAddr string, amount eth2p0.Gwei) (eth2p0.DepositMessage, error) {
	creds, err := withdrawalCredsFromAddr(withdrawalAddr)
	if err != nil {
		return eth2p0.DepositMessage{}, err
	}

	if amount < MinDepositAmount {
		return eth2p0.DepositMessage{}, errors.New("deposit message minimum amount must be >= 1ETH", z.U64("amount", uint64(amount)))
	}

	if amount > MaxDepositAmount {
		return eth2p0.DepositMessage{}, errors.New("deposit message maximum amount exceeded", z.U64("amount", uint64(amount)), z.U64("max", uint64(MaxDepositAmount)))
	}

	return eth2p0.DepositMessage{
		PublicKey:             pubkey,
		WithdrawalCredentials: creds[:],
		Amount:                amount,
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
			PubKey:                hex.EncodeToString(depositData.PublicKey[:]),
			WithdrawalCredentials: hex.EncodeToString(depositData.WithdrawalCredentials),
			Amount:                uint64(depositData.Amount),
			Signature:             hex.EncodeToString(depositData.Signature[:]),
			DepositMessageRoot:    hex.EncodeToString(msgRoot[:]),
			DepositDataRoot:       hex.EncodeToString(dataRoot[:]),
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
	copy(creds[0:], eip7251AddressWithdrawalPrefix) // Add 1 byte prefix.
	copy(creds[12:], addrBytes)                     // Add 20 bytes of ethereum address suffix.

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

// VerifyDepositAmounts verifies various conditions about partial deposits rules.
func VerifyDepositAmounts(amounts []eth2p0.Gwei) error {
	if len(amounts) == 0 {
		// If no partial amounts specified, the implementation shall default to 32ETH.
		return nil
	}

	for _, amount := range amounts {
		if amount < MinDepositAmount {
			return errors.New("partial deposit amount must be greater than 1ETH", z.U64("amount", uint64(amount)))
		}
		if amount > MaxDepositAmount {
			return errors.New("partial deposit amount must not exceed 2048ETH", z.U64("sum", uint64(amount)))
		}
	}

	return nil
}

// EthsToGweis converts amounts from []int (ETH) to []eth2p0.Gwei.
// For verification, please see VerifyDepositAmounts().
func EthsToGweis(ethAmounts []int) []eth2p0.Gwei {
	if ethAmounts == nil {
		return nil
	}

	var gweiAmounts []eth2p0.Gwei
	for _, ethAmount := range ethAmounts {
		gwei := eth2p0.Gwei(OneEthInGwei * ethAmount)
		gweiAmounts = append(gweiAmounts, gwei)
	}

	return gweiAmounts
}

// DedupAmounts returns duplicated amounts in ascending order.
func DedupAmounts(amounts []eth2p0.Gwei) []eth2p0.Gwei {
	var result []eth2p0.Gwei
	used := make(map[eth2p0.Gwei]struct{})

	for _, amount := range amounts {
		if _, amountUsed := used[amount]; amountUsed {
			continue
		}
		used[amount] = struct{}{}
		result = append(result, amount)
	}

	slices.Sort(result)

	return result
}

// AddDefaultDepositAmounts adds MinDepositAmount and DefaultDepositAmount to the amounts list.
func AddDefaultDepositAmounts(amounts []eth2p0.Gwei) []eth2p0.Gwei {
	amounts = append(amounts, MinDepositAmount, DefaultDepositAmount)

	return DedupAmounts(amounts)
}

// WriteClusterDepositDataFiles writes deposit-data-*eth.json files for each distinct amount.
func WriteClusterDepositDataFiles(depositDatas [][]eth2p0.DepositData, network string, clusterDir string, numNodes int) error {
	// The loop across partial amounts (shall be unique)
	for _, dd := range depositDatas {
		for n := range numNodes {
			nodeDir := path.Join(clusterDir, fmt.Sprintf("node%d", n))
			if err := WriteDepositDataFile(dd, network, nodeDir); err != nil {
				return err
			}
		}
	}

	return nil
}

// WriteDepositDataFile writes deposit-data-*eth.json file for the provided depositDatas.
// The amount will be reflected in the filename in ETH.
// All depositDatas amounts shall have equal values.
func WriteDepositDataFile(depositDatas []eth2p0.DepositData, network string, dataDir string) error {
	if len(depositDatas) == 0 {
		return errors.New("empty deposit data")
	}

	for i, dd := range depositDatas {
		if i == 0 {
			continue
		}

		if depositDatas[0].Amount != dd.Amount {
			return errors.New("deposit datas has different amount", z.Int("index", i))
		}
	}

	bytes, err := MarshalDepositData(depositDatas, network)
	if err != nil {
		return err
	}

	depositFilePath := GetDepositFilePath(dataDir, depositDatas[0].Amount)

	//nolint:gosec // File needs to be read-only for everybody
	err = os.WriteFile(depositFilePath, bytes, 0o444)
	if err != nil {
		return errors.Wrap(err, "write deposit data")
	}

	return nil
}

// GetDepositFilePath constructs and return deposit-data file path.
func GetDepositFilePath(dataDir string, amount eth2p0.Gwei) string {
	var filename string
	if amount == DefaultDepositAmount {
		// For backward compatibility, use the old filename.
		filename = "deposit-data.json"
	} else {
		eth := float64(amount) / float64(OneEthInGwei)
		ethStr := strconv.FormatFloat(eth, 'f', -1, 64)
		filename = fmt.Sprintf("deposit-data-%seth.json", ethStr)
	}

	return path.Join(dataDir, filename)
}
