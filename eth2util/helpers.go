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

package eth2util

import (
	"context"
	"encoding/hex"
	"strings"
	"unicode"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

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

// ChecksumAddress returns an EIP55-compliant 0xhex representation of the 0xhex ethereum address.
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
