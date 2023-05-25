// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatorapi

import (
	"context"
	"fmt"
	"time"
)

type TekuProposerConfigResponse struct {
	Proposers map[string]TekuProposerConfig `json:"proposer_config"`
	Default   TekuProposerConfig            `json:"default_config"`
}

type TekuProposerConfig struct {
	FeeRecipient string      `json:"fee_recipient"`
	Builder      TekuBuilder `json:"builder"`
}

type TekuBuilder struct {
	Enabled   bool              `json:"enabled"`
	GasLimit  uint              `json:"gas_limit"`
	Overrides map[string]string `json:"registration_overrides,omitempty"`
}

const (
	gasLimit    = 30000000
	zeroAddress = "0x0000000000000000000000000000000000000000"
)

type TekuProposerConfigProvider interface {
	TekuProposerConfig(ctx context.Context) (TekuProposerConfigResponse, error)
}

func (c Component) TekuProposerConfig(ctx context.Context) (TekuProposerConfigResponse, error) {
	resp := TekuProposerConfigResponse{
		Proposers: make(map[string]TekuProposerConfig),
		Default: TekuProposerConfig{ // Default doesn't make sense, disable for now.
			FeeRecipient: zeroAddress,
			Builder: TekuBuilder{
				Enabled:  false,
				GasLimit: gasLimit,
			},
		},
	}

	slotDuration, err := c.eth2Cl.SlotDuration(ctx)
	if err != nil {
		return TekuProposerConfigResponse{}, err
	}

	timestamp, err := c.eth2Cl.GenesisTime(ctx)
	if err != nil {
		return TekuProposerConfigResponse{}, err
	}
	timestamp = timestamp.Add(slotDuration) // Use slot 1 for timestamp to override pre-generated registrations.

	slot, err := c.slotFromTimestamp(ctx, time.Now())
	if err != nil {
		return TekuProposerConfigResponse{}, err
	}

	for pubkey, pubshare := range c.sharesByKey {
		resp.Proposers[string(pubshare)] = TekuProposerConfig{
			FeeRecipient: c.feeRecipientFunc(pubkey),
			Builder: TekuBuilder{
				Enabled:  c.builderEnabled(int64(slot)),
				GasLimit: gasLimit,
				Overrides: map[string]string{
					"timestamp":  fmt.Sprint(timestamp.Unix()),
					"public_key": string(pubkey),
				},
			},
		}
	}

	return resp, nil
}
