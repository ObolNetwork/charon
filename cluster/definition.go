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

	ssz "github.com/ferranbt/fastssz"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

// NodeIdx represents the index of a node/peer/share in the cluster as operator order in cluster definition.
type NodeIdx struct {
	// PeerIdx is the index of a peer in the peer list (it 0-indexed).
	PeerIdx int
	// ShareIdx is the tbls share identifier (it is 1-indexed).
	ShareIdx int
}

// NewDefinition returns a new definition populated with the latest version, timestamp and UUID.
func NewDefinition(name string, numVals int, threshold int, feeRecipient string, withdrawalAddress string,
	forkVersionHex string, operators []Operator, random io.Reader,
) Definition {
	return Definition{
		Version:             currentVersion,
		Name:                name,
		UUID:                uuid(random),
		Timestamp:           time.Now().Format(time.RFC3339),
		NumValidators:       numVals,
		Threshold:           threshold,
		FeeRecipientAddress: feeRecipient,
		WithdrawalAddress:   withdrawalAddress,
		DKGAlgorithm:        dkgAlgo,
		ForkVersion:         forkVersionHex,
		Operators:           operators,
	}
}

// Definition defines an intended charon cluster configuration.
type Definition struct {
	// Name is an optional cosmetic identifier
	Name string

	// UUID is a random unique identifier
	UUID string

	// Version is the schema version of this definition.
	Version string

	// Timestamp is the human readable timestamp of this definition.
	// Note that this was added in v1.1.0, so may be empty for older versions.
	Timestamp string

	// NumValidators is the number of DVs (n*32ETH) to be created in the cluster lock file.
	NumValidators int

	// Threshold required for signature reconstruction. Defaults to safe value for number of nodes/peers.
	Threshold int

	// FeeRecipientAddress Ethereum address.
	FeeRecipientAddress string

	// WithdrawalAddress Ethereum address.
	WithdrawalAddress string

	// DKGAlgorithm to use for key generation.
	DKGAlgorithm string

	// ForkVersion defines the cluster's beacon chain hex fork definitionVersion (network/chain identifier).
	ForkVersion string

	// Operators define the charon nodes in the cluster and their operators.
	Operators []Operator
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

// Verify returns true if all config signatures are fully populated and valid. A verified definition is ready for use in DKG.
func (d Definition) Verify() error {
	configHash, err := d.ConfigHash()
	if err != nil {
		return errors.Wrap(err, "config hash")
	}

	for _, o := range d.Operators {
		if len(o.ENRSignature) == 0 {
			return errors.New("empty operator enr signature", z.Str("operator_address", o.Address))
		}

		if len(o.ConfigSignature) == 0 {
			return errors.New("empty operator config signature", z.Str("operator_address", o.Address))
		}

		// Check that we have a valid config signature for each operator.
		digest, err := digestEIP712(o.Address, configHash[:], 0)
		if err != nil {
			return err
		}

		if ok, err := verifySig(o.Address, digest[:], o.ConfigSignature); err != nil {
			return err
		} else if !ok {
			return errors.New("invalid operator config signature", z.Str("operator_address", o.Address))
		}

		// Check that we have a valid enr signature for each operator.
		digest, err = digestEIP712(o.Address, []byte(o.ENR), 0)
		if err != nil {
			return err
		}

		if ok, err := verifySig(o.Address, digest[:], o.ENRSignature); err != nil {
			return err
		} else if !ok {
			return errors.New("invalid operator enr signature", z.Str("operator_address", o.Address))
		}
	}

	return nil
}

// ConfigHash returns the config hash of the definition object.
func (d Definition) ConfigHash() ([32]byte, error) {
	return configHash(d)
}

// GetTree ssz hashes the Definition object.
func (d Definition) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(d) //nolint:wrapcheck
}

// HashTreeRoot ssz hashes the Definition object.
func (d Definition) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(d) //nolint:wrapcheck
}

// HashTreeRootWith ssz hashes the Definition object by including all the fields inside Operator.
// This is done in order to calculate definition_hash of the final Definition object.
func (d Definition) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	// Field (0) 'UUID'
	hh.PutBytes([]byte(d.UUID))

	// Field (1) 'Name'
	hh.PutBytes([]byte(d.Name))

	// Field (2) 'Version'
	hh.PutBytes([]byte(d.Version))

	// Field (3) 'NumValidators'
	hh.PutUint64(uint64(d.NumValidators))

	// Field (4) 'Threshold'
	hh.PutUint64(uint64(d.Threshold))

	// Field (5) 'FeeRecipientAddress'
	hh.PutBytes([]byte(d.FeeRecipientAddress))

	// Field (6) 'WithdrawalAddress'
	hh.PutBytes([]byte(d.WithdrawalAddress))

	// Field (7) 'DKGAlgorithm'
	hh.PutBytes([]byte(d.DKGAlgorithm))

	// Field (8) 'ForkVersion'
	hh.PutBytes([]byte(d.ForkVersion))

	// Field (9) 'Operators'
	{
		subIndx := hh.Index()
		num := uint64(len(d.Operators))
		for _, operator := range d.Operators {
			if err := operator.HashTreeRootWith(hh); err != nil {
				return err
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, num)
	}

	// Field (10) 'timestamp' (optional only added from v1.1.0)
	if d.Version != v1_0 {
		hh.PutBytes([]byte(d.Timestamp))
	}

	hh.Merkleize(indx)

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

func (d Definition) MarshalJSON() ([]byte, error) {
	// Marshal config hash
	configHash, err := d.ConfigHash()
	if err != nil {
		return nil, errors.Wrap(err, "config hash")
	}

	// Marshal definition hash
	defHash, err := d.HashTreeRoot()
	if err != nil {
		return nil, errors.Wrap(err, "definition hash")
	}

	switch {
	case isJSONv1x1(d.Version):
		return marshalDefinitionV1x1(d, configHash, defHash)
	case isJSONv1x2(d.Version):
		return marshalDefinitionV1x2(d, configHash, defHash)
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
		def            Definition
		configHashJSON []byte
		defHashJSON    []byte
		err            error
	)
	switch {
	case isJSONv1x1(version.Version):
		def, configHashJSON, defHashJSON, err = unmarshalDefinitionV1x1(data)
		if err != nil {
			return err
		}
	case isJSONv1x2(version.Version):
		def, configHashJSON, defHashJSON, err = unmarshalDefinitionV1x2(data)
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported version")
	}

	// Verify config_hash
	configHash, err := def.ConfigHash()
	if err != nil {
		return errors.Wrap(err, "config hash")
	}

	if !bytes.Equal(configHashJSON, configHash[:]) {
		return errors.New("invalid config hash")
	}

	// Verify definition_hash
	defHash, err := def.HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "definition hash")
	}

	if !bytes.Equal(defHashJSON, defHash[:]) {
		return errors.New("invalid definition hash")
	}

	*d = def

	return nil
}

func marshalDefinitionV1x1(def Definition, configHash, defHash [32]byte) ([]byte, error) {
	resp, err := json.Marshal(definitionJSONv1x1{
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
		Operators:           operatorsToV1x1(def.Operators),
		ConfigHash:          configHash[:],
		DefinitionHash:      defHash[:],
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal definition")
	}

	return resp, nil
}

func marshalDefinitionV1x2(def Definition, configHash, defHash [32]byte) ([]byte, error) {
	resp, err := json.Marshal(definitionJSONv1x2{
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
		ConfigHash:          configHash[:],
		DefinitionHash:      defHash[:],
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal definition")
	}

	return resp, nil
}

func unmarshalDefinitionV1x1(data []byte) (def Definition, configHashJSON, defHashJSON []byte, err error) {
	var defJSON definitionJSONv1x1
	if err := json.Unmarshal(data, &defJSON); err != nil {
		return Definition{}, nil, nil, errors.Wrap(err, "unmarshal definition v1_1")
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
		Operators:           operatorsFromV1x1(defJSON.Operators),
	}

	return def, defJSON.ConfigHash, defJSON.DefinitionHash, nil
}

func unmarshalDefinitionV1x2(data []byte) (def Definition, configHashJSON, defHashJSON []byte, err error) {
	var defJSON definitionJSONv1x2
	if err := json.Unmarshal(data, &defJSON); err != nil {
		return Definition{}, nil, nil, errors.Wrap(err, "unmarshal definition v1v2")
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
		Operators:           operatorsFromV1x2(defJSON.Operators),
	}

	return def, defJSON.ConfigHash, defJSON.DefinitionHash, nil
}

// definitionJSONv1x1 is the json formatter of Definition for versions v1.0.0 and v1.1.1.
type definitionJSONv1x1 struct {
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

// definitionJSONv1x2 is the json formatter of Definition for versions v1.2.0 and later.
type definitionJSONv1x2 struct {
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
	ForkVersion         string             `json:"fork_version"`
	ConfigHash          ethHex             `json:"config_hash"`
	DefinitionHash      ethHex             `json:"definition_hash"`
}
