// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util

import (
	"context"
	"encoding/hex"
	"regexp"
	"strings"
	"unicode"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

// ValidateBeaconNodeHeaders validates the format of a string containing beacon node headers.
func ValidateBeaconNodeHeaders(headers []string) error {
	if len(headers) > 0 {
		// The pattern ([^=,]+) captures any string that does not contain '=' or ','.
		// The composition of patterns ([^=,]+)=([^=,]+) captures a pair of header and its corresponding value.
		// We use ^ at the start and $ at the end to ensure exact match.
		headerPattern := regexp.MustCompile(`^([^=,]+)=([^,]+)$`)
		for _, header := range headers {
			if !headerPattern.MatchString(header) {
				return errors.New("beacon node headers must be comma separated values formatted as header=value")
			}
		}
	}

	return nil
}

// ParseBeaconNodeHeader validates and parses a string of headers into a map of key-value pairs.
// Returns empty map if string is empty.
func ParseBeaconNodeHeaders(headers []string) (map[string]string, error) {
	parsedHeaders := make(map[string]string)
	if len(headers) == 0 {
		return parsedHeaders, nil
	}

	err := ValidateBeaconNodeHeaders(headers)
	if err != nil {
		return nil, err
	}

	for _, header := range headers {
		pair := strings.SplitN(header, "=", 2)
		parsedHeaders[pair[0]] = pair[1]
	}

	return parsedHeaders, nil
}

// EpochFromSlot returns epoch calculated from given slot.
func EpochFromSlot(ctx context.Context, eth2Cl eth2client.SlotsPerEpochProvider, slot eth2p0.Slot) (eth2p0.Epoch, error) {
	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return 0, errors.Wrap(err, "getting slots per epoch")
	}

	return eth2p0.Epoch(uint64(slot) / slotsPerEpoch), nil
}

// ChecksumAddress returns an EIP55-compliant 0xhex representation of the 0xhex ethereum address.
func ChecksumAddress(address string) (string, error) {
	if !strings.HasPrefix(address, "0x") || len(address) != 2+20*2 {
		return "", errors.New("invalid ethereum address", z.Str("address", address))
	}
	b, err := hex.DecodeString(address[2:])
	if err != nil {
		return "", errors.New("invalid ethereum hex address", z.Str("address", address))
	}

	return checksumAddressBytes(b), nil
}

// ChecksumAddress returns an EIP55-compliant 0xhex representation of the binary ethereum address.
func checksumAddressBytes(addressBytes []byte) string {
	hexAddr := hex.EncodeToString(addressBytes)

	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write([]byte(hexAddr))
	hexHash := hex.EncodeToString(h.Sum(nil))

	resp := []rune{'0', 'x'}
	for i, c := range []rune(hexAddr) {
		if c > '9' && hexHash[i] > '7' {
			c = unicode.ToUpper(c)
		}
		resp = append(resp, c)
	}

	return string(resp)
}

// PublicKeyToAddress returns the EIP55-compliant 0xhex ethereum address of the public key.
func PublicKeyToAddress(pubkey *k1.PublicKey) string {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(pubkey.SerializeUncompressed()[1:])

	return checksumAddressBytes(h.Sum(nil)[12:])
}
