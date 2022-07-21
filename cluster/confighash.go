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

import ssz "github.com/ferranbt/fastssz"

// staticDefinition defines the static (non-changing) portion of the charon cluster definition.
// The fields are a subset of the Definition struct excluding full Operator structs.
type staticDefinition struct {
	name                string
	uuid                string
	version             string
	timestamp           string
	numValidators       int
	threshold           int
	feeRecipientAddress string
	withdrawalAddress   string
	dkgAlgorithm        string
	forkVersion         string
	addresses           []string
}

// HashTreeRoot ssz hashes the staticDefinition object.
func (d staticDefinition) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(d) //nolint:wrapcheck
}

// HashTreeRootWith ssz hashes the staticDefinition object by including all the fields inside Operator.
// This is done in order to calculate definition_hash of the final Definition object.
func (d staticDefinition) HashTreeRootWith(hh *ssz.Hasher) error {
	indx := hh.Index()

	// Field (0) 'uuid'
	hh.PutBytes([]byte(d.uuid))

	// Field (1) 'name'
	hh.PutBytes([]byte(d.name))

	// Field (2) 'version'
	hh.PutBytes([]byte(d.version))

	// Field (3) 'numValidators'
	hh.PutUint64(uint64(d.numValidators))

	// Field (4) 'threshold'
	hh.PutUint64(uint64(d.threshold))

	// Field (5) 'feeRecipientAddress'
	hh.PutBytes([]byte(d.feeRecipientAddress))

	// Field (6) 'withdrawalAddress'
	hh.PutBytes([]byte(d.withdrawalAddress))

	// Field (7) 'dkgAlgorithm'
	hh.PutBytes([]byte(d.dkgAlgorithm))

	// Field (8) 'forkVersion'
	hh.PutBytes([]byte(d.forkVersion))

	// Field (9) 'addresses'
	{
		subIndx := hh.Index()
		num := uint64(len(d.addresses))
		for _, addr := range d.addresses {
			hh.PutBytes([]byte(addr))
		}
		hh.MerkleizeWithMixin(subIndx, num, num)
	}

	// Field (10) 'timestamp' (optional for backwards compatibility)
	if d.timestamp != "" {
		hh.PutBytes([]byte(d.timestamp))
	}

	hh.Merkleize(indx)

	return nil
}

// configHash returns the config hash of the given cluster definition object. The config hash is the
// ssz hash of all the static fields of the definition object and hence doesn't change once created.
func configHash(d Definition) ([32]byte, error) {
	sd := staticDefinition{
		name:                d.Name,
		uuid:                d.UUID,
		version:             d.Version,
		timestamp:           d.Timestamp,
		numValidators:       d.NumValidators,
		threshold:           d.Threshold,
		feeRecipientAddress: d.FeeRecipientAddress,
		withdrawalAddress:   d.WithdrawalAddress,
		dkgAlgorithm:        d.DKGAlgorithm,
		forkVersion:         d.ForkVersion,
		addresses:           nil,
	}

	var addrs []string
	for _, op := range d.Operators {
		addrs = append(addrs, op.Address)
	}

	sd.addresses = addrs

	return sd.HashTreeRoot()
}
