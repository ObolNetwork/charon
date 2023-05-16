// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package registration

import (
	"encoding/hex"
	"strings"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
)

// DOMAIN_APPLICATION_BUILDER. See https://github.com/ethereum/builder-specs/blob/7b269305e1e54f22ddb84b3da2f222e20adf6e4f/specs/bellatrix/builder.md#domain-types.
var registrationDomainType = eth2p0.DomainType([4]byte{0x00, 0x00, 0x00, 0x01})

// NewMessage returns a v1.ValidatorRegistration message with the provided pubkey, feeRecipient, gasLimit and timestamp.
func NewMessage(pubkey eth2p0.BLSPubKey, feeRecipient string, gasLimit uint64, timestamp time.Time) (eth2v1.ValidatorRegistration, error) {
	execAddr, err := executionAddressFromStr(feeRecipient)
	if err != nil {
		return eth2v1.ValidatorRegistration{}, err
	}

	return eth2v1.ValidatorRegistration{
		FeeRecipient: execAddr,
		GasLimit:     gasLimit,
		Timestamp:    timestamp,
		Pubkey:       pubkey,
	}, nil
}

// executionAddressFromStr returns the address corresponding to a '0x01' Ethereum withdrawal address.
func executionAddressFromStr(addr string) ([20]byte, error) {
	// Check for validity of address.
	if _, err := eth2util.ChecksumAddress(addr); err != nil {
		return [20]byte{}, errors.Wrap(err, "invalid address", z.Str("addr", addr))
	}

	addrBytes, err := hex.DecodeString(strings.TrimPrefix(addr, "0x"))
	if err != nil {
		return [20]byte{}, errors.Wrap(err, "decode address")
	}

	if len(addrBytes) > 20 {
		return [20]byte{}, errors.New("address has wrong length", z.Int("length", len(addrBytes)))
	}

	return [20]byte(addrBytes), nil
}

// getRegistrationDomain returns the validator registration signature domain.
func getRegistrationDomain() (eth2p0.Domain, error) {
	forkData := &eth2p0.ForkData{
		CurrentVersion:        eth2p0.Version{}, // CurrentVersion is zero for validator registration,
		GenesisValidatorsRoot: eth2p0.Root{},    // GenesisValidatorsRoot is zero for validator registration.
	}

	root, err := forkData.HashTreeRoot()
	if err != nil {
		return eth2p0.Domain{}, errors.Wrap(err, "hash fork data")
	}

	var domain eth2p0.Domain
	copy(domain[0:], registrationDomainType[:])
	copy(domain[4:], root[:])

	return domain, nil
}

// GetMessageSigningRoot returns the validator registration message signing root created by the provided parameters.
func GetMessageSigningRoot(msg eth2v1.ValidatorRegistration) ([32]byte, error) {
	msgRoot, err := msg.HashTreeRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "validator registration message root")
	}

	domain, err := getRegistrationDomain()
	if err != nil {
		return [32]byte{}, err
	}

	resp, err := (&eth2p0.SigningData{ObjectRoot: msgRoot, Domain: domain}).HashTreeRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "signing data root")
	}

	return resp, nil
}
