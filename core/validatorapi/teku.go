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

package validatorapi

import (
	"context"
	"fmt"
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

const gasLimit = 30000000

type TekuProposerConfigProvider interface {
	TekuProposerConfig(ctx context.Context) (TekuProposerConfigResponse, error)
}

func (c Component) TekuProposerConfig(ctx context.Context) (TekuProposerConfigResponse, error) {
	resp := TekuProposerConfigResponse{
		Proposers: make(map[string]TekuProposerConfig),
		Default: TekuProposerConfig{ // Default doesn't make sense, disable for now.
			FeeRecipient: c.feeRecipient,
			Builder: TekuBuilder{
				Enabled:  false,
				GasLimit: gasLimit,
			},
		},
	}

	genesis, err := c.eth2Cl.GenesisTime(ctx)
	if err != nil {
		return TekuProposerConfigResponse{}, nil
	}

	for pubkey, pubshare := range c.sharesByKey {
		resp.Proposers[string(pubshare)] = TekuProposerConfig{
			FeeRecipient: c.feeRecipient,
			Builder: TekuBuilder{
				Enabled:  true,
				GasLimit: gasLimit,
				Overrides: map[string]string{
					"timestamp":  fmt.Sprint(genesis.Unix()),
					"public_key": string(pubkey),
				},
			},
		}
	}

	return resp, nil
}
