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

package cluster

import (
	"bytes"
	"encoding/json"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/p2p"
)

const (
	forkVersionLen = 4
	addressLen     = 20
)

// NodeIdx represents the index of a node/peer/share in the cluster as operator order in cluster definition.
type NodeIdx struct {
	// PeerIdx is the index of a peer in the peer list (it 0-indexed).
	PeerIdx int
	// ShareIdx is the tbls share identifier (it is 1-indexed).
	ShareIdx int
}

// NewDefinition returns a new definition populated with the latest version, timestamp and UUID.
func NewDefinition(name string, numVals int, threshold int, feeRecipientAddress string, withdrawalAddress string,
	forkVersionHex string, operators []Operator, random io.Reader,
) (Definition, error) {
	def := Definition{
		Version:             currentVersion,
		Name:                name,
		UUID:                uuid(random),
		Timestamp:           time.Now().Format(time.RFC3339),
		NumValidators:       numVals,
		Threshold:           threshold,
		DKGAlgorithm:        dkgAlgo,
		WithdrawalAddress:   withdrawalAddress,
		FeeRecipientAddress: feeRecipientAddress,
		Operators:           operators,
	}

	var err error
	def.ForkVersion, err = from0xHex(forkVersionHex, forkVersionLen)
	if err != nil {
		return Definition{}, err
	}

	return def, nil
}

// Definition defines an intended charon cluster configuration excluding validators.
// Note the following struct tag meanings:
//   - json: json field name. Suffix 0xhex indicates bytes are formatted as 0x prefixed hex strings.
//   - ssz: ssz equivalent. Either uint64 for numbers, BytesN for fixed length bytes, ByteList[MaxN]
//     for variable length strings, or CompositeList[MaxN] for nested object arrays.
//   - config_hash: field ordering when calculating config hash. Some fields are excluded indicated by `-`.
//   - definition_hash: field ordering when calculating definition hash. Some fields are excluded indicated by `-`.
type Definition struct {
	// UUID is a human-readable random unique identifier. Max 64 chars.
	UUID string `json:"uuid" ssz:"ByteList[64]" config_hash:"0" definition_hash:"0"`

	// Name is a human-readable cosmetic identifier. Max 256 chars.
	Name string `json:"name" ssz:"ByteList[256]" config_hash:"1" definition_hash:"1"`

	// Version is the schema version of this definition. Max 16 chars.
	Version string `json:"version" ssz:"ByteList[16]" config_hash:"2" definition_hash:"2"`

	// Timestamp is the human-readable timestamp of this definition. Max 32 chars.
	// Note that this was added in v1.1.0, so may be empty for older versions.
	Timestamp string `json:"timestamp" ssz:"ByteList[32]" config_hash:"3" definition_hash:"3"`

	// NumValidators is the number of DVs (n*32ETH) to be created in the cluster lock file.
	NumValidators int `json:"num_validators" ssz:"uint64" config_hash:"4" definition_hash:"4"`

	// Threshold required for signature reconstruction. Defaults to safe value for number of nodes/peers.
	Threshold int `json:"threshold" ssz:"uint64" config_hash:"5" definition_hash:"5"`

	// FeeRecipientAddress 20 byte Ethereum address.
	FeeRecipientAddress string `json:"fee_recipient_address,0xhex" ssz:"Bytes20" config_hash:"6" definition_hash:"6"`

	// WithdrawalAddress 20 byte Ethereum address.
	WithdrawalAddress string `json:"withdrawal_address,0xhex" ssz:"Bytes20" config_hash:"7" definition_hash:"7"`

	// DKGAlgorithm to use for key generation. Max 32 chars.
	DKGAlgorithm string `json:"dkg_algorithm" ssz:"ByteList[32]" config_hash:"8" definition_hash:"8"`

	// ForkVersion defines the cluster's 4 byte beacon chain fork version (network/chain identifier).
	ForkVersion []byte `json:"fork_version,0xhex" ssz:"Bytes4" config_hash:"9" definition_hash:"9"`

	// Operators define the charon nodes in the cluster and their operators. Max 256 operators.
	Operators []Operator `json:"operators" ssz:"CompositeList[256]" config_hash:"10" definition_hash:"10"`

	// ConfigHash uniquely identifies a cluster definition excluding operator ENRs and signatures.
	ConfigHash []byte `json:"config_hash,0xhex" ssz:"Bytes32" config_hash:"-" definition_hash:"11"`

	// DefinitionHash uniquely identifies a cluster definition including operator ENRs and signatures.
	DefinitionHash []byte `json:"definition_hash,0xhex" ssz:"Bytes32" config_hash:"-" definition_hash:"-"`
}

// NodeIdx returns the node index for the peer.
func (d Definition) NodeIdx(pID peer.ID) (NodeIdx, error) {
	peers, err := d.Peers()
	if err != nil {
		return NodeIdx{}, err
	}

	for i, p := range peers {
		if p.ID != pID {
			continue
		}

		return NodeIdx{
			PeerIdx:  i,     // 0-indexed
			ShareIdx: i + 1, // 1-indexed
		}, nil
	}

	return NodeIdx{}, errors.New("peer not in definition")
}

// VerifySignatures returns true if all config signatures are fully populated and valid. A verified definition is ready for use in DKG.
func (d Definition) VerifySignatures() error {
	// Skip signature verification for definition versions earlier than v1.3 since there are no EIP712 signatures before v1.3.0.
	if !supportEIP712Sigs(d.Version) {
		return nil
	}

	configHash, err := hashDefinition(d, true)
	if err != nil {
		return errors.Wrap(err, "config hash")
	}

	chainID, err := eth2util.ForkVersionToChainID(d.ForkVersion)
	if err != nil {
		return errors.Wrap(err, "fork version to chain id")
	}

	var noSigs int
	for _, o := range d.Operators {
		// Completely unsigned operators are also fine, assuming a single cluster-wide operator.
		if o.Address == "" && len(o.ENRSignature) == 0 && len(o.ConfigSignature) == 0 {
			noSigs++
			continue
		}

		if len(o.ENRSignature) == 0 {
			return errors.New("empty operator enr signature", z.Any("operator_address", o.Address))
		}

		if len(o.ConfigSignature) == 0 {
			return errors.New("empty operator config signature", z.Any("operator_address", o.Address))
		}

		// Check that we have a valid config signature for each operator.
		digest, err := digestEIP712(eip712TypeConfigHash, to0xHex(configHash[:]), chainID)
		if err != nil {
			return err
		}

		if ok, err := verifySig(o.Address, digest[:], o.ConfigSignature); err != nil {
			return err
		} else if !ok {
			return errors.New("invalid operator config signature", z.Any("operator_address", o.Address))
		}

		// Check that we have a valid enr signature for each operator.
		digest, err = digestEIP712(eip712TypeENR, o.ENR, chainID)
		if err != nil {
			return err
		}

		if ok, err := verifySig(o.Address, digest[:], o.ENRSignature); err != nil {
			return err
		} else if !ok {
			return errors.New("invalid operator enr signature", z.Any("operator_address", o.Address))
		}
	}

	if noSigs > 0 && noSigs != len(d.Operators) {
		return errors.New("some operators signed while others didn't")
	}

	return nil
}

// Peers returns the operators as a slice of p2p peers.
func (d Definition) Peers() ([]p2p.Peer, error) {
	var resp []p2p.Peer
	for i, operator := range d.Operators {
		record, err := p2p.DecodeENR(operator.ENR)
		if err != nil {
			return nil, err
		}

		p, err := p2p.NewPeer(record, i)
		if err != nil {
			return nil, err
		}

		resp = append(resp, p)
	}

	return resp, nil
}

// PeerIDs is a convenience function that returns the operators p2p peer IDs.
func (d Definition) PeerIDs() ([]peer.ID, error) {
	peers, err := d.Peers()
	if err != nil {
		return nil, err
	}
	var resp []peer.ID
	for _, p := range peers {
		resp = append(resp, p.ID)
	}

	return resp, nil
}

// SetDefinitionHashes returns a copy of the definition with the config hash and definition hash populated.
func (d Definition) SetDefinitionHashes() (Definition, error) {
	// Marshal config hash
	configHash, err := hashDefinition(d, true)
	if err != nil {
		return Definition{}, errors.Wrap(err, "config hash")
	}

	d.ConfigHash = configHash[:]

	// Marshal definition hashDefinition
	defHash, err := hashDefinition(d, false)
	if err != nil {
		return Definition{}, errors.Wrap(err, "definition hashDefinition")
	}

	d.DefinitionHash = defHash[:]

	return d, nil
}

func (d Definition) MarshalJSON() ([]byte, error) {
	d, err := d.SetDefinitionHashes()
	if err != nil {
		return nil, err
	}

	switch {
	case isJSONv1x0(d.Version) || isJSONv1x1(d.Version):
		return marshalDefinitionV1x0or1(d)
	case isJSONv1x2(d.Version) || isJSONv1x3(d.Version):
		// v1.2 and v1.3 has the same json format.
		return marshalDefinitionV1x2or3(d)
	default:
		return nil, errors.New("unsupported version")
	}
}

func (d *Definition) UnmarshalJSON(data []byte) error {
	// Get the version directly
	version := struct {
		Version string `json:"version"`
	}{}
	if err := json.Unmarshal(data, &version); err != nil {
		return errors.Wrap(err, "unmarshal version")
	} else if !supportedVersions[version.Version] {
		return errors.New("unsupported definition version",
			z.Str("version", version.Version),
			z.Any("supported", supportedVersions),
		)
	}

	var (
		def Definition
		err error
	)
	switch {
	case isJSONv1x0(version.Version) || isJSONv1x1(version.Version):
		def, err = unmarshalDefinitionV1x0or1(data)
		if err != nil {
			return err
		}
	case isJSONv1x2(version.Version) || isJSONv1x3(version.Version):
		def, err = unmarshalDefinitionV1x2or3(data)
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported version")
	}

	*d = def

	// For definition versions earlier than v1.3.0, error if either config signature or enr signature for any operator is present.
	if !supportEIP712Sigs(def.Version) {
		for _, o := range def.Operators {
			if len(o.ENRSignature) > 0 || len(o.ConfigSignature) > 0 {
				return errors.New("older version signatures not supported")
			}
		}
	}

	return nil
}

// VerifyHashes returns an error if hashes populated from json object doesn't matches actual hashes.
func (d Definition) VerifyHashes() error {
	configHash, err := hashDefinition(d, true)
	if err != nil {
		return errors.Wrap(err, "config hash")
	}

	if !bytes.Equal(d.ConfigHash, configHash[:]) {
		return errors.New("invalid config hash")
	}

	// Verify definition_hash
	defHash, err := hashDefinition(d, false)
	if err != nil {
		return errors.Wrap(err, "definition hash")
	}

	if !bytes.Equal(d.DefinitionHash, defHash[:]) {
		return errors.New("invalid definition hash")
	}

	return nil
}

func marshalDefinitionV1x0or1(def Definition) ([]byte, error) {
	resp, err := json.Marshal(definitionJSONv1x0or1{
		Name:                def.Name,
		UUID:                def.UUID,
		Version:             def.Version,
		Timestamp:           def.Timestamp,
		NumValidators:       def.NumValidators,
		Threshold:           def.Threshold,
		FeeRecipientAddress: def.FeeRecipientAddress,
		WithdrawalAddress:   def.WithdrawalAddress,
		DKGAlgorithm:        def.DKGAlgorithm,
		ForkVersion:         to0xHex(def.ForkVersion),
		Operators:           operatorsToV1x1(def.Operators),
		ConfigHash:          def.ConfigHash,
		DefinitionHash:      def.DefinitionHash,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal definition")
	}

	return resp, nil
}

func marshalDefinitionV1x2or3(def Definition) ([]byte, error) {
	resp, err := json.Marshal(definitionJSONv1x2or3{
		Name:                def.Name,
		UUID:                def.UUID,
		Version:             def.Version,
		Timestamp:           def.Timestamp,
		NumValidators:       def.NumValidators,
		Threshold:           def.Threshold,
		FeeRecipientAddress: def.FeeRecipientAddress,
		WithdrawalAddress:   def.WithdrawalAddress,
		DKGAlgorithm:        def.DKGAlgorithm,
		ForkVersion:         def.ForkVersion,
		Operators:           operatorsToV1x2(def.Operators),
		ConfigHash:          def.ConfigHash,
		DefinitionHash:      def.DefinitionHash,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal definition")
	}

	return resp, nil
}

func unmarshalDefinitionV1x0or1(data []byte) (def Definition, err error) {
	var defJSON definitionJSONv1x0or1
	if err := json.Unmarshal(data, &defJSON); err != nil {
		return Definition{}, errors.Wrap(err, "unmarshal definition v1_1")
	}

	operators, err := operatorsFromV1x1(defJSON.Operators)
	if err != nil {
		return Definition{}, err
	}

	def = Definition{
		Name:                defJSON.Name,
		UUID:                defJSON.UUID,
		Version:             defJSON.Version,
		Timestamp:           defJSON.Timestamp,
		NumValidators:       defJSON.NumValidators,
		Threshold:           defJSON.Threshold,
		DKGAlgorithm:        defJSON.DKGAlgorithm,
		ConfigHash:          defJSON.ConfigHash,
		DefinitionHash:      defJSON.DefinitionHash,
		Operators:           operators,
		FeeRecipientAddress: defJSON.FeeRecipientAddress,
		WithdrawalAddress:   defJSON.WithdrawalAddress,
	}

	def.ForkVersion, err = from0xHex(defJSON.ForkVersion, forkVersionLen)
	if err != nil {
		return Definition{}, err
	}

	return def, nil
}

func unmarshalDefinitionV1x2or3(data []byte) (def Definition, err error) {
	var defJSON definitionJSONv1x2or3
	if err := json.Unmarshal(data, &defJSON); err != nil {
		return Definition{}, errors.Wrap(err, "unmarshal definition v1v2")
	}

	def = Definition{
		Name:                defJSON.Name,
		UUID:                defJSON.UUID,
		Version:             defJSON.Version,
		Timestamp:           defJSON.Timestamp,
		NumValidators:       defJSON.NumValidators,
		Threshold:           defJSON.Threshold,
		FeeRecipientAddress: defJSON.FeeRecipientAddress,
		WithdrawalAddress:   defJSON.WithdrawalAddress,
		DKGAlgorithm:        defJSON.DKGAlgorithm,
		ForkVersion:         defJSON.ForkVersion,
		ConfigHash:          defJSON.ConfigHash,
		DefinitionHash:      defJSON.DefinitionHash,
		Operators:           operatorsFromV1x2or3(defJSON.Operators),
	}

	return def, nil
}

func supportEIP712Sigs(version string) bool {
	return !isJSONv1x0(version) && !isJSONv1x1(version) && !isJSONv1x2(version)
}

// definitionJSONv1x0or1 is the json formatter of Definition for versions v1.0.0 and v1.1.1.
type definitionJSONv1x0or1 struct {
	Name                string             `json:"name,omitempty"`
	Operators           []operatorJSONv1x1 `json:"operators"`
	UUID                string             `json:"uuid"`
	Version             string             `json:"version"`
	Timestamp           string             `json:"timestamp,omitempty"`
	NumValidators       int                `json:"num_validators"`
	Threshold           int                `json:"threshold"`
	FeeRecipientAddress string             `json:"fee_recipient_address,omitempty"`
	WithdrawalAddress   string             `json:"withdrawal_address,omitempty"`
	DKGAlgorithm        string             `json:"dkg_algorithm"`
	ForkVersion         string             `json:"fork_version"`
	ConfigHash          []byte             `json:"config_hash"`
	DefinitionHash      []byte             `json:"definition_hash"`
}

// definitionJSONv1x2or3 is the json formatter of Definition for versions v1.2.0 and later.
type definitionJSONv1x2or3 struct {
	Name                string             `json:"name,omitempty"`
	Operators           []operatorJSONv1x2 `json:"operators"`
	UUID                string             `json:"uuid"`
	Version             string             `json:"version"`
	Timestamp           string             `json:"timestamp,omitempty"`
	NumValidators       int                `json:"num_validators"`
	Threshold           int                `json:"threshold"`
	FeeRecipientAddress string             `json:"fee_recipient_address,omitempty"`
	WithdrawalAddress   string             `json:"withdrawal_address,omitempty"`
	DKGAlgorithm        string             `json:"dkg_algorithm"`
	ForkVersion         ethHex             `json:"fork_version"`
	ConfigHash          ethHex             `json:"config_hash"`
	DefinitionHash      ethHex             `json:"definition_hash"`
}
