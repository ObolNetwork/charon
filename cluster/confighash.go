package cluster

import ssz "github.com/ferranbt/fastssz"

// StaticDefinition defines the static (non-changing) portion of the charon cluster definition.
type StaticDefinition struct {
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
	Addresses []string
}

// HashTreeRoot ssz hashes the StaticDefinition object.
func (d StaticDefinition) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(d) //nolint:wrapcheck
}

// HashTreeRootWith ssz hashes the StaticDefinition object by including all the fields inside Operator.
// This is done in order to calculate definition_hash of the final Definition object.
func (d StaticDefinition) HashTreeRootWith(hh *ssz.Hasher) error {
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

	// Field (9) 'Addresses'
	{
		subIndx := hh.Index()
		num := uint64(len(d.Addresses))
		for _, addr := range d.Addresses {
			hh.PutBytes([]byte(addr))
		}
		hh.MerkleizeWithMixin(subIndx, num, num)
	}

	hh.Merkleize(indx)

	return nil
}

// ConfigHash returns the config hash of the given cluster definition object. The config hash is the
// ssz hash of all the static fields of the definition object and hence doesn't change once created.
func ConfigHash(d Definition) ([32]byte, error) {
	sd := StaticDefinition{
		Name:                d.Name,
		UUID:                d.UUID,
		Version:             d.Version,
		NumValidators:       d.NumValidators,
		Threshold:           d.Threshold,
		FeeRecipientAddress: d.FeeRecipientAddress,
		WithdrawalAddress:   d.WithdrawalAddress,
		DKGAlgorithm:        d.DKGAlgorithm,
		ForkVersion:         d.ForkVersion,
		Addresses:           nil,
	}

	var addrs []string
	for _, op := range d.Operators {
		addrs = append(addrs, op.Address)
	}

	sd.Addresses = addrs

	return sd.HashTreeRoot()
}
