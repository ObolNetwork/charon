// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package proposerconfig

import (
	"encoding/hex"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
)

// ParseProposal returns the unsigned revision held by a proposal file, its config as written in the file.
func ParseProposal(b []byte) (Document, error) {
	file, err := decodeConfigFile(b)
	if err != nil {
		return Document{}, err
	}

	if file.LockHash == "" {
		return Document{}, errors.New("lock_hash is required in a proposal file")
	}

	lockHash, err := decodeHex(file.LockHash)
	if err != nil {
		return Document{}, errors.Wrap(err, "decode lock_hash")
	}

	if file.Revision == 0 {
		return Document{}, errors.New("revision must be greater than 0 in a proposal file")
	}

	return Document{
		Version:  file.Version,
		LockHash: lockHash,
		Revision: file.Revision,
		Config:   Config{DefaultConfig: file.DefaultConfig, ProposerConfig: file.ProposerConfig},
	}, nil
}

// MarshalProposal returns the proposal file holding the document's lock hash, revision and config.
func MarshalProposal(doc Document) ([]byte, error) {
	return marshalConfigFile(configFile{
		Version:        Version,
		LockHash:       "0x" + hex.EncodeToString(doc.LockHash),
		Revision:       doc.Revision,
		DefaultConfig:  doc.Config.DefaultConfig,
		ProposerConfig: doc.Config.ProposerConfig,
	})
}

// zeroAddress is the fee recipient no proposal may set.
const zeroAddress = "0x0000000000000000000000000000000000000000"

// ApplyProposal returns the proposal in the canonical form Apply builds, or ErrNoChange if it equals c. Like the
// change flags, a proposal cannot remove a validator's fee recipient or set the zero address.
func ApplyProposal(lock cluster.Lock, c, proposal Config) (Config, error) {
	// Keys differing only in case would collide in any order once lowercased.
	for key := range proposal.ProposerConfig {
		if key != strings.ToLower(key) {
			return Config{}, errors.New("proposer_config key must be lowercase", z.Str("key", key))
		}
	}

	norm, err := Normalise(proposal)
	if err != nil {
		return Config{}, err
	}

	err = checkEditableFields(norm, lock)
	if err != nil {
		return Config{}, err
	}

	fees := norm.FeeRecipients(lock)
	for i, current := range c.FeeRecipients(lock) {
		switch {
		case fees[i] == zeroAddress && current != zeroAddress:
			return Config{}, errors.New("zero fee recipient forbidden", z.Int("validator", i))
		case fees[i] == "" && current != "":
			return Config{}, errors.New("fee recipient must not be removed", z.Int("validator", i))
		}
	}

	seed, err := seedFromSettings(norm.DefaultConfig)
	if err != nil {
		return Config{}, err
	}

	err = validateBuilderURLs("default_config.builder.builders", seed.BuilderURLs)
	if err != nil {
		return Config{}, err
	}

	res, err := NewConfigWithDefault(lock, norm.DefaultConfig.FeeRecipient, fees, seed.GasLimit, seed.Builder())
	if err != nil {
		return Config{}, err
	}

	equal, err := SameConfig(c, res)
	if err != nil {
		return Config{}, err
	}

	if equal {
		return Config{}, ErrNoChange
	}

	return res, nil
}
