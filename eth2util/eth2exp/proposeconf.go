// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2exp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
)

const (
	builderOverrideTimestamp = "timestamp"
	builderOverridePublicKey = "public_key"
)

// ProposerConfigProvider is the interface for providing proposer configuration.
type ProposerConfigProvider interface {
	ProposerConfig(ctx context.Context) (*ProposerConfigResponse, error)
}

// ProposerConfigResponse is the response from the proposer config endpoint.
type ProposerConfigResponse struct {
	Proposers map[eth2p0.BLSPubKey]ProposerConfig
	Default   ProposerConfig
}

func (p ProposerConfigResponse) MarshalJSON() ([]byte, error) {
	resp := &proposerConfigResponseJSON{
		Proposers: make(map[string]ProposerConfig),
		Default:   p.Default,
	}
	for k, v := range p.Proposers {
		resp.Proposers[fmt.Sprintf("%#x", k)] = v
	}

	b, err := json.Marshal(resp)
	if err != nil {
		return nil, errors.Wrap(err, "marshal proposer config response")
	}

	return b, nil
}

func (p *ProposerConfigResponse) UnmarshalJSON(input []byte) error {
	resp := new(proposerConfigResponseJSON)
	if err := json.Unmarshal(input, resp); err != nil {
		return errors.Wrap(err, "unmarshal proposer config response")
	}

	p.Proposers = make(map[eth2p0.BLSPubKey]ProposerConfig)

	for k, v := range resp.Proposers {
		pkBytes, err := hex.DecodeString(strings.TrimPrefix(k, "0x"))
		if err != nil {
			return errors.Wrap(err, "decode proposer public key")
		}
		if len(pkBytes) != 48 {
			return errors.New("invalid proposer public key")
		}

		p.Proposers[eth2p0.BLSPubKey(pkBytes)] = v
	}

	p.Default = resp.Default

	return nil
}

// ProposerConfig is the configuration for a proposer.
type ProposerConfig struct {
	FeeRecipient string  `json:"fee_recipient"`
	Builder      Builder `json:"builder"`
}

// Builder is the build-API configuration for a proposer.
type Builder struct {
	Enabled   bool              `json:"enabled"`
	GasLimit  uint              `json:"gas_limit"`
	Overrides map[string]string `json:"registration_overrides,omitempty"`
}

// TimestampOverride returns the timestamp override and true if it exists.
func (b Builder) TimestampOverride() (time.Time, bool, error) {
	ts, ok := b.Overrides[builderOverrideTimestamp]
	if !ok {
		return time.Time{}, false, nil
	}

	tsUnix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return time.Time{}, false, errors.Wrap(err, "parse timestamp override")
	}

	return time.Unix(tsUnix, 0), true, nil
}

// PublicKeyOverride returns the public key override and true if it exists.
func (b Builder) PublicKeyOverride() (eth2p0.BLSPubKey, bool, error) {
	pk, ok := b.Overrides[builderOverridePublicKey]
	if !ok {
		return eth2p0.BLSPubKey{}, false, nil
	}

	pkBytes, err := hex.DecodeString(strings.TrimPrefix(pk, "0x"))
	if err != nil {
		return eth2p0.BLSPubKey{}, false, errors.Wrap(err, "parse public key override")
	} else if len(pkBytes) != 48 {
		return eth2p0.BLSPubKey{}, false, errors.New("invalid public key override")
	}

	return eth2p0.BLSPubKey(pkBytes), true, nil
}

type proposerConfigResponseJSON struct {
	Proposers map[string]ProposerConfig `json:"proposer_config"`
	Default   ProposerConfig            `json:"default_config"`
}
