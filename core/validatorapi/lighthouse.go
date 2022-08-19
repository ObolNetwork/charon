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

type LighthouseValidatorDefinition struct {
	Enabled                    bool   `json:"enabled"`
	VotingPublicKey            string `json:"voting_public_key"`
	Type                       string `json:"type"`
	VotingKeystorePath         string `json:"voting_keystore_path"`
	VotingKeystorePasswordPath string `json:"voting_keystore_password_path"`
	SuggestedFeeRecipient      string `json:"suggested_fee_recipient"`
	GasLimit                   uint   `json:"gas_limit"`
	BuilderProposals           bool   `json:"builder_proposals"`
	BuilderPubkeyOverride      string `json:"builder_pubkey_override"`
}

const gasLimit = 30000000

type LighthouseValidatorDefinitionsProvider interface {
	LighthouseValidatorDefinitions() ([]LighthouseValidatorDefinition, error)
}

func (c Component) LighthouseValidatorDefinitions() ([]LighthouseValidatorDefinition, error) {
	var resp []LighthouseValidatorDefinition

	for pubkey, pubshare := range c.sharesByKey {
		resp = append(resp, LighthouseValidatorDefinition{
			Enabled:               true,
			VotingPublicKey:       string(pubshare),
			SuggestedFeeRecipient: c.feeRecipient,
			GasLimit:              gasLimit,
			BuilderProposals:      true,
			BuilderPubkeyOverride: string(pubkey),
		})
	}

	return resp, nil
}
