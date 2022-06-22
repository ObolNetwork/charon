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

	ssz "github.com/ferranbt/fastssz"
	"github.com/libp2p/go-libp2p-core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/p2p"
)

const (
	definitionVersion = "v1.0.0"
	dkgAlgo           = "default"
)

// NodeIdx represents the index of a node/peer/share in the cluster as operator order in cluster definition.
type NodeIdx struct {
	// PeerIdx is the index of a peer in the peer list (it 0-indexed).
	PeerIdx int
	// ShareIdx is the tbls share identifier (it is 1-indexed).
	ShareIdx int
}

// NewDefinition returns a new definition with populated version and UUID.
func NewDefinition(
	name string,
	numVals int,
	threshold int,
	feeRecipient string,
	withdrawalAddress string,
	forkVersionHex string,
	operators []Operator,
	random io.Reader,
) Definition {
	s := Definition{
		Version:             definitionVersion,
		Name:                name,
		UUID:                uuid(random),
		NumValidators:       numVals,
		Threshold:           threshold,
		FeeRecipientAddress: feeRecipient,
		WithdrawalAddress:   withdrawalAddress,
		DKGAlgorithm:        dkgAlgo,
		ForkVersion:         forkVersionHex,
		Operators:           operators,
	}

	return s
}

// Definition defines an intended charon cluster configuration.
type Definition struct {
	// Name is an optional cosmetic identifier
	Name string

	// UUID is a random unique identifier
	UUID string

	// Version is the schema version of this definition.
	Version string

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

	return NodeIdx{}, errors.New("unknown peer id")
}

// Sealed returns true if all config signatures are fully populated and valid. A "sealed" definition is ready for use in DKG.
func (d Definition) Sealed() (bool, error) {
	configHash, err := d.ConfigHash()
	if err != nil {
		return false, errors.Wrap(err, "config hash")
	}

	for _, o := range d.Operators {
		// Check that we have a valid config signature for each operator.
		digest, err := digestEIP712(o.Address, configHash[:], 0)
		if err != nil {
			return false, err
		}

		if ok, err := verifySig(o.Address, digest[:], o.ConfigSignature); err != nil {
			return false, err
		} else if !ok {
			return false, errors.Wrap(err, "config signature mismatch")
		}

		// Check that we have a valid enr signature for each operator.
		digest, err = digestEIP712(o.Address, []byte(o.ENR), 0)
		if err != nil {
			return false, err
		}

		if ok, err := verifySig(o.Address, digest[:], o.ENRSignature); err != nil {
			return false, err
		} else if !ok {
			return false, errors.Wrap(err, "enr signature mismatch")
		}
	}

	return true, nil
}

// ConfigHash returns the config hash of the definition object.
func (d Definition) ConfigHash() ([32]byte, error) {
	return configHash(d)
}

// HashTreeRoot ssz hashes the Definition object.
func (d Definition) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(d) //nolint:wrapcheck
}

// HashTreeRootWith ssz hashes the Definition object by including all the fields inside Operator.
// This is done in order to calculate definition_hash of the final Definition object.
func (d Definition) HashTreeRootWith(hh *ssz.Hasher) error {
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

	hh.Merkleize(indx)

	return nil
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

	// Marshal json version of lock
	resp, err := json.Marshal(defFmt{
		Name:                d.Name,
		UUID:                d.UUID,
		Version:             d.Version,
		NumValidators:       d.NumValidators,
		Threshold:           d.Threshold,
		FeeRecipientAddress: d.FeeRecipientAddress,
		WithdrawalAddress:   d.WithdrawalAddress,
		DKGAlgorithm:        d.DKGAlgorithm,
		ForkVersion:         d.ForkVersion,
		Operators:           d.Operators,
		ConfigHash:          configHash[:],
		DefinitionHash:      defHash[:],
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal lock")
	}

	return resp, nil
}

func (d *Definition) UnmarshalJSON(data []byte) error {
	// Get the version directly
	version := struct {
		Version string `json:"version"`
	}{}
	if err := json.Unmarshal(data, &version); err != nil {
		return errors.Wrap(err, "unmarshal version")
	} else if version.Version != definitionVersion {
		return errors.Wrap(err, "invalid definition version")
	}

	var defFmt defFmt
	if err := json.Unmarshal(data, &defFmt); err != nil {
		return errors.Wrap(err, "unmarshal definition")
	}

	def := Definition{
		Name:                defFmt.Name,
		UUID:                defFmt.UUID,
		Version:             defFmt.Version,
		NumValidators:       defFmt.NumValidators,
		Threshold:           defFmt.Threshold,
		FeeRecipientAddress: defFmt.FeeRecipientAddress,
		WithdrawalAddress:   defFmt.WithdrawalAddress,
		DKGAlgorithm:        defFmt.DKGAlgorithm,
		ForkVersion:         defFmt.ForkVersion,
		Operators:           defFmt.Operators,
	}

	// Verify config_hash
	configHash, err := def.ConfigHash()
	if err != nil {
		return errors.Wrap(err, "config hash")
	}

	if !bytes.Equal(defFmt.ConfigHash, configHash[:]) {
		return errors.New("invalid config hash")
	}

	// Verify definition_hash
	defHash, err := def.HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "definition hash")
	}

	if !bytes.Equal(defFmt.DefinitionHash, defHash[:]) {
		return errors.New("invalid definition hash")
	}

	*d = def

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

// defFmt is the json formatter of Definition.
type defFmt struct {
	Name                string     `json:"name,omitempty"`
	Operators           []Operator `json:"operators"`
	UUID                string     `json:"uuid"`
	Version             string     `json:"version"`
	NumValidators       int        `json:"num_validators"`
	Threshold           int        `json:"threshold"`
	FeeRecipientAddress string     `json:"fee_recipient_address,omitempty"`
	WithdrawalAddress   string     `json:"withdrawal_address,omitempty"`
	DKGAlgorithm        string     `json:"dkg_algorithm"`
	ForkVersion         string     `json:"fork_version"`
	ConfigHash          []byte     `json:"config_hash"`
	DefinitionHash      []byte     `json:"definition_hash"`
}
