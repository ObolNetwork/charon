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

type LighthouseValidatorDefinitionJSON struct {
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

// type LighthouseValidatorDefinitionYAML struct {
// 	Enabled                    bool   `yaml:"enabled"`
// 	VotingPublicKey            string `yaml:"voting_public_key"`
// 	Type                       string `yaml:"type"`
// 	VotingKeystorePath         string `yaml:"voting_keystore_path"`
// 	VotingKeystorePasswordPath string `yaml:"voting_keystore_password_path"`
// 	SuggestedFeeRecipient      string `yaml:"suggested_fee_recipient"`
// 	GasLimit                   uint   `yaml:"gas_limit"`
// 	BuilderProposals           bool   `yaml:"builder_proposals"`
// 	BuilderPubkeyOverride      string `yaml:"builder_pubkey_override"`
// }

const gasLimit = 30000000

type LighthouseValidatorDefinitionsProvider interface {
	LighthouseValidatorDefinitions() ([]LighthouseValidatorDefinitionJSON, error)
}

func (c Component) LighthouseValidatorDefinitions() ([]LighthouseValidatorDefinitionJSON, error) {
	resp := []LighthouseValidatorDefinitionJSON{}

	for pubkey, pubshare := range c.sharesByKey {
		resp = append(resp, LighthouseValidatorDefinitionJSON{
			Enabled:         true,
			VotingPublicKey: string(pubshare),
			// Asking whether these need to be defined in lighthouse discord
			// Type: dead,
			// VotingKeystorePath: dead,
			// VotingKeystorePasswordPath: dead,
			SuggestedFeeRecipient: string(pubkey),
			GasLimit:              gasLimit,
			BuilderProposals:      true,
			BuilderPubkeyOverride: dead,
		})
	}

	return resp, nil
}
