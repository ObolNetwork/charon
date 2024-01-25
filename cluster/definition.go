// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	"bytes"
	"encoding/json"
	"io"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/enr"
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

// WithVersion returns an option to set a non-default version in a new definition.
func WithVersion(version string) func(*Definition) {
	return func(d *Definition) {
		d.Version = version
	}
}

// WithLegacyVAddrs returns an option to set single feeRecipient address and withdrawal address to validator addresses.
func WithLegacyVAddrs(feeRecipientAddress, withdrawalAddress string) func(*Definition) {
	return func(d *Definition) {
		var vAddrs []ValidatorAddresses
		for i := 0; i < d.NumValidators; i++ {
			vAddrs = append(vAddrs, ValidatorAddresses{
				FeeRecipientAddress: feeRecipientAddress,
				WithdrawalAddress:   withdrawalAddress,
			})
		}

		d.ValidatorAddresses = vAddrs
	}
}

// NewDefinition returns a new definition populated with the latest version, timestamp and UUID.
// The hashes are also populated accordingly. Note that the hashes need to be recalculated when any field is modified.
func NewDefinition(name string, numVals int, threshold int, feeRecipientAddresses []string, withdrawalAddresses []string,
	forkVersionHex string, creator Creator, operators []Operator, random io.Reader, opts ...func(*Definition),
) (Definition, error) {
	if len(feeRecipientAddresses) != numVals {
		return Definition{}, errors.New("insufficient fee-recipient addresses")
	}

	if len(withdrawalAddresses) != numVals {
		return Definition{}, errors.New("insufficient fee-recipient addresses")
	}

	def := Definition{
		Version:       currentVersion,
		Name:          name,
		UUID:          uuid(random),
		Timestamp:     time.Now().Format(time.RFC3339),
		NumValidators: numVals,
		Threshold:     threshold,
		DKGAlgorithm:  dkgAlgo,
		Operators:     operators,
		Creator:       creator,
	}

	for i := 0; i < numVals; i++ {
		def.ValidatorAddresses = append(def.ValidatorAddresses, ValidatorAddresses{
			FeeRecipientAddress: feeRecipientAddresses[i],
			WithdrawalAddress:   withdrawalAddresses[i],
		})
	}

	var err error
	def.ForkVersion, err = from0xHex(forkVersionHex, forkVersionLen)
	if err != nil {
		return Definition{}, err
	}

	for _, opt := range opts {
		opt(&def)
	}

	return def.SetDefinitionHashes()
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
	UUID string `config_hash:"0" definition_hash:"0" json:"uuid" ssz:"ByteList[64]"`

	// Name is a human-readable cosmetic identifier. Max 256 chars.
	Name string `config_hash:"1" definition_hash:"1" json:"name" ssz:"ByteList[256]"`

	// Version is the schema version of this definition. Max 16 chars.
	Version string `config_hash:"2" definition_hash:"2" json:"version" ssz:"ByteList[16]"`

	// Timestamp is the human-readable timestamp of this definition. Max 32 chars.
	// Note that this was added in v1.1.0, so may be empty for older versions.
	Timestamp string `config_hash:"3" definition_hash:"3" json:"timestamp" ssz:"ByteList[32]"`

	// NumValidators is the number of DVs (n*32ETH) to be created in the cluster lock file.
	NumValidators int `config_hash:"4" definition_hash:"4" json:"num_validators" ssz:"uint64"`

	// Threshold required for signature reconstruction. Defaults to safe value for number of nodes/peers.
	Threshold int `config_hash:"5" definition_hash:"5" json:"threshold" ssz:"uint64"`

	// DKGAlgorithm to use for key generation. Max 32 chars.
	DKGAlgorithm string `config_hash:"6" definition_hash:"6" json:"dkg_algorithm" ssz:"ByteList[32]"`

	// ForkVersion defines the cluster's 4 byte beacon chain fork version (network/chain identifier).
	ForkVersion []byte `json:"fork_version,0xhex" ssz:"Bytes4" config_hash:"7" definition_hash:"7"`

	// Operators define the charon nodes in the cluster and their operators. Max 256 operators.
	Operators []Operator `config_hash:"8" definition_hash:"8" json:"operators" ssz:"CompositeList[256]"`

	// Creator identifies the creator of a cluster definition. They may also be an operator.
	Creator Creator `config_hash:"9" definition_hash:"9" json:"creator" ssz:"Composite"`

	// ValidatorAddresses define addresses of each validator.
	ValidatorAddresses []ValidatorAddresses `config_hash:"10" definition_hash:"10" json:"validators" ssz:"CompositeList[65536]"`

	// DepositAmounts specifies partial deposit amounts that sum up to 32ETH.
	DepositAmounts []eth2p0.Gwei `definition_hash:"11" deposit_amounts:"11" json:"deposit_amounts" ssz:"uint64[256]"`

	// ConfigHash uniquely identifies a cluster definition excluding operator ENRs and signatures.
	ConfigHash []byte `json:"config_hash,0xhex" ssz:"Bytes32" config_hash:"-" definition_hash:"12"`

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

// VerifySignatures returns nil if all config signatures are fully populated and valid. A verified definition is ready for use in DKG.
func (d Definition) VerifySignatures() error {
	// Skip signature verification for definition versions earlier than v1.3 since there are no EIP712 signatures before v1.3.0.
	if !supportEIP712Sigs(d.Version) && !eip712SigsPresent(d.Operators) {
		return nil
	}

	// For definition versions earlier than v1.3.0, error if either config signature or enr signature for any operator is present.
	if !supportEIP712Sigs(d.Version) && eip712SigsPresent(d.Operators) {
		return errors.New("older version signatures not supported")
	}

	// Check valid operator config signature for each operator.
	operatorConfigHashDigest, err := digestEIP712(getOperatorEIP712Type(d.Version), d, Operator{})
	if err != nil {
		return err
	}

	var noOpSigs int
	for _, o := range d.Operators {
		// Completely unsigned operators are also fine, assuming a single cluster-wide operator.
		if o.Address == "" && len(o.ENRSignature) == 0 && len(o.ConfigSignature) == 0 {
			noOpSigs++
			continue
		}

		if len(o.ENRSignature) == 0 {
			return errors.New("empty operator enr signature", z.Any("operator_address", o.Address))
		}

		if len(o.ConfigSignature) == 0 {
			return errors.New("empty operator config signature", z.Any("operator_address", o.Address))
		}

		if ok, err := verifySig(o.Address, operatorConfigHashDigest, o.ConfigSignature); err != nil {
			return err
		} else if !ok {
			return errors.New("invalid operator config signature", z.Any("operator_address", o.Address))
		}

		// Check that we have a valid enr signature for each operator.
		enrDigest, err := digestEIP712(eip712ENR, d, o)
		if err != nil {
			return err
		}

		if ok, err := verifySig(o.Address, enrDigest, o.ENRSignature); err != nil {
			return err
		} else if !ok {
			return errors.New("invalid operator enr signature", z.Any("operator_address", o.Address))
		}
	}

	if noOpSigs > 0 && noOpSigs != len(d.Operators) {
		return errors.New("some operators signed while others didn't")
	}

	// Verify creator signature
	if isAnyVersion(d.Version, v1_3) {
		if len(d.Creator.ConfigSignature) > 0 {
			return errors.New("unexpected creator config signature in old version")
		}
	} else if d.Creator.Address == "" && len(d.Creator.ConfigSignature) == 0 {
		// Empty creator is fine if also not operator signatures either.
		if noOpSigs == 0 {
			return errors.New("operators signed while creator didn't")
		}
	} else {
		if len(d.Creator.ConfigSignature) == 0 {
			return errors.New("empty creator config signature")
		}

		// Creator config signature is
		creatorConfigHashDigest, err := digestEIP712(eip712CreatorConfigHash, d, Operator{})
		if err != nil {
			return err
		}

		if ok, err := verifySig(d.Creator.Address, creatorConfigHashDigest, d.Creator.ConfigSignature); err != nil {
			return err
		} else if !ok {
			return errors.New("invalid creator config signature")
		}
	}

	return nil
}

// Peers returns the operators as a slice of p2p peers.
func (d Definition) Peers() ([]p2p.Peer, error) {
	var resp []p2p.Peer
	dedup := make(map[string]bool)
	for i, operator := range d.Operators {
		if dedup[operator.ENR] {
			return nil, errors.New("definition contains duplicate peer enrs", z.Str("enr", operator.ENR))
		}
		dedup[operator.ENR] = true

		record, err := enr.Parse(operator.ENR)
		if err != nil {
			return nil, errors.Wrap(err, "decode enr", z.Str("enr", operator.ENR))
		}

		p, err := p2p.NewPeerFromENR(record, i)
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

// LegacyValidatorAddresses returns the legacy single withdrawal and single fee recipient addresses
// or an error if multiple addresses are found.
func (d Definition) LegacyValidatorAddresses() (ValidatorAddresses, error) {
	var resp ValidatorAddresses
	for i, vaddrs := range d.ValidatorAddresses {
		if i == 0 {
			resp = vaddrs
		} else if resp != vaddrs {
			return ValidatorAddresses{}, errors.New("multiple withdrawal or fee recipient addresses found")
		}
	}

	return resp, nil
}

// WithdrawalAddresses is a convenience function to return all withdrawal address from the validator addresses slice.
func (d Definition) WithdrawalAddresses() []string {
	var resp []string
	for _, vaddrs := range d.ValidatorAddresses {
		resp = append(resp, vaddrs.WithdrawalAddress)
	}

	return resp
}

// FeeRecipientAddresses is a convenience function to return all fee-recipient address from the validator addresses slice.
func (d Definition) FeeRecipientAddresses() []string {
	var resp []string
	for _, vaddrs := range d.ValidatorAddresses {
		resp = append(resp, vaddrs.FeeRecipientAddress)
	}

	return resp
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
	d2, err := d.SetDefinitionHashes()
	if err != nil {
		return nil, err
	}

	switch {
	case isAnyVersion(d2.Version, v1_0, v1_1):
		return marshalDefinitionV1x0or1(d2)
	case isAnyVersion(d2.Version, v1_2, v1_3):
		// v1.2 and v1.3 has the same json format.
		return marshalDefinitionV1x2or3(d2)
	case isAnyVersion(d2.Version, v1_4):
		return marshalDefinitionV1x4(d2)
	case isAnyVersion(d2.Version, v1_5, v1_6, v1_7):
		return marshalDefinitionV1x5to7(d2)
	case isAnyVersion(d2.Version, v1_8):
		return marshalDefinitionV1x8(d2)
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
	case isAnyVersion(version.Version, v1_0, v1_1):
		def, err = unmarshalDefinitionV1x0or1(data)
		if err != nil {
			return err
		}
	case isAnyVersion(version.Version, v1_2, v1_3):
		def, err = unmarshalDefinitionV1x2or3(data)
		if err != nil {
			return err
		}
	case isAnyVersion(version.Version, v1_4):
		def, err = unmarshalDefinitionV1x4(data)
		if err != nil {
			return err
		}
	case isAnyVersion(version.Version, v1_5, v1_6, v1_7):
		def, err = unmarshalDefinitionV1x5to7(data)
		if err != nil {
			return err
		}
	case isAnyVersion(version.Version, v1_8):
		def, err = unmarshalDefinitionV1x8(data)
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported version")
	}

	*d = def

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
	vaddrs, err := def.LegacyValidatorAddresses()
	if err != nil {
		return nil, err
	}

	resp, err := json.Marshal(definitionJSONv1x0or1{
		Name:                def.Name,
		UUID:                def.UUID,
		Version:             def.Version,
		Timestamp:           def.Timestamp,
		NumValidators:       def.NumValidators,
		Threshold:           def.Threshold,
		FeeRecipientAddress: vaddrs.FeeRecipientAddress,
		WithdrawalAddress:   vaddrs.WithdrawalAddress,
		DKGAlgorithm:        def.DKGAlgorithm,
		ForkVersion:         to0xHex(def.ForkVersion),
		Operators:           operatorsToV1x1(def.Operators),
		ConfigHash:          def.ConfigHash,
		DefinitionHash:      def.DefinitionHash,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal definition v1.0")
	}

	return resp, nil
}

func marshalDefinitionV1x2or3(def Definition) ([]byte, error) {
	vaddrs, err := def.LegacyValidatorAddresses()
	if err != nil {
		return nil, err
	}

	resp, err := json.Marshal(definitionJSONv1x2or3{
		Name:                def.Name,
		UUID:                def.UUID,
		Version:             def.Version,
		Timestamp:           def.Timestamp,
		NumValidators:       def.NumValidators,
		Threshold:           def.Threshold,
		FeeRecipientAddress: vaddrs.FeeRecipientAddress,
		WithdrawalAddress:   vaddrs.WithdrawalAddress,
		DKGAlgorithm:        def.DKGAlgorithm,
		ForkVersion:         def.ForkVersion,
		Operators:           operatorsToV1x2orLater(def.Operators),
		ConfigHash:          def.ConfigHash,
		DefinitionHash:      def.DefinitionHash,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal definition v1.1")
	}

	return resp, nil
}

func marshalDefinitionV1x4(def Definition) ([]byte, error) {
	vaddrs, err := def.LegacyValidatorAddresses()
	if err != nil {
		return nil, err
	}

	resp, err := json.Marshal(definitionJSONv1x4{
		Name:                def.Name,
		UUID:                def.UUID,
		Version:             def.Version,
		Timestamp:           def.Timestamp,
		NumValidators:       def.NumValidators,
		Threshold:           def.Threshold,
		FeeRecipientAddress: vaddrs.FeeRecipientAddress,
		WithdrawalAddress:   vaddrs.WithdrawalAddress,
		DKGAlgorithm:        def.DKGAlgorithm,
		ForkVersion:         def.ForkVersion,
		ConfigHash:          def.ConfigHash,
		DefinitionHash:      def.DefinitionHash,
		Operators:           operatorsToV1x2orLater(def.Operators),
		Creator: creatorJSON{
			Address:         def.Creator.Address,
			ConfigSignature: def.Creator.ConfigSignature,
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal definition v1.4")
	}

	return resp, nil
}

func marshalDefinitionV1x5to7(def Definition) ([]byte, error) {
	resp, err := json.Marshal(definitionJSONv1x5{
		Name:               def.Name,
		UUID:               def.UUID,
		Version:            def.Version,
		Timestamp:          def.Timestamp,
		NumValidators:      def.NumValidators,
		Threshold:          def.Threshold,
		DKGAlgorithm:       def.DKGAlgorithm,
		ValidatorAddresses: validatorAddressesToJSON(def.ValidatorAddresses),
		ForkVersion:        def.ForkVersion,
		ConfigHash:         def.ConfigHash,
		DefinitionHash:     def.DefinitionHash,
		Operators:          operatorsToV1x2orLater(def.Operators),
		Creator: creatorJSON{
			Address:         def.Creator.Address,
			ConfigSignature: def.Creator.ConfigSignature,
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal definition v1.5")
	}

	return resp, nil
}

func marshalDefinitionV1x8(def Definition) ([]byte, error) {
	resp, err := json.Marshal(definitionJSONv1x8{
		Name:               def.Name,
		UUID:               def.UUID,
		Version:            def.Version,
		Timestamp:          def.Timestamp,
		NumValidators:      def.NumValidators,
		Threshold:          def.Threshold,
		DKGAlgorithm:       def.DKGAlgorithm,
		ValidatorAddresses: validatorAddressesToJSON(def.ValidatorAddresses),
		ForkVersion:        def.ForkVersion,
		ConfigHash:         def.ConfigHash,
		DefinitionHash:     def.DefinitionHash,
		Operators:          operatorsToV1x2orLater(def.Operators),
		Creator: creatorJSON{
			Address:         def.Creator.Address,
			ConfigSignature: def.Creator.ConfigSignature,
		},
		DepositAmounts: def.DepositAmounts,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal definition v1.8")
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

	vaddrs := ValidatorAddresses{
		FeeRecipientAddress: defJSON.FeeRecipientAddress,
		WithdrawalAddress:   defJSON.WithdrawalAddress,
	}

	def = Definition{
		Name:               defJSON.Name,
		UUID:               defJSON.UUID,
		Version:            defJSON.Version,
		Timestamp:          defJSON.Timestamp,
		NumValidators:      defJSON.NumValidators,
		Threshold:          defJSON.Threshold,
		DKGAlgorithm:       defJSON.DKGAlgorithm,
		ConfigHash:         defJSON.ConfigHash,
		DefinitionHash:     defJSON.DefinitionHash,
		Operators:          operators,
		ValidatorAddresses: repeatVAddrs(vaddrs, defJSON.NumValidators),
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

	vaddrs := ValidatorAddresses{
		FeeRecipientAddress: defJSON.FeeRecipientAddress,
		WithdrawalAddress:   defJSON.WithdrawalAddress,
	}

	def = Definition{
		Name:               defJSON.Name,
		UUID:               defJSON.UUID,
		Version:            defJSON.Version,
		Timestamp:          defJSON.Timestamp,
		NumValidators:      defJSON.NumValidators,
		Threshold:          defJSON.Threshold,
		DKGAlgorithm:       defJSON.DKGAlgorithm,
		ForkVersion:        defJSON.ForkVersion,
		ConfigHash:         defJSON.ConfigHash,
		DefinitionHash:     defJSON.DefinitionHash,
		Operators:          operatorsFromV1x2orLater(defJSON.Operators),
		ValidatorAddresses: repeatVAddrs(vaddrs, defJSON.NumValidators),
	}

	return def, nil
}

func unmarshalDefinitionV1x4(data []byte) (def Definition, err error) {
	var defJSON definitionJSONv1x4
	if err := json.Unmarshal(data, &defJSON); err != nil {
		return Definition{}, errors.Wrap(err, "unmarshal definition v1v2")
	}

	vaddrs := ValidatorAddresses{
		FeeRecipientAddress: defJSON.FeeRecipientAddress,
		WithdrawalAddress:   defJSON.WithdrawalAddress,
	}

	return Definition{
		Name:               defJSON.Name,
		UUID:               defJSON.UUID,
		Version:            defJSON.Version,
		Timestamp:          defJSON.Timestamp,
		NumValidators:      defJSON.NumValidators,
		Threshold:          defJSON.Threshold,
		DKGAlgorithm:       defJSON.DKGAlgorithm,
		ForkVersion:        defJSON.ForkVersion,
		ConfigHash:         defJSON.ConfigHash,
		DefinitionHash:     defJSON.DefinitionHash,
		Operators:          operatorsFromV1x2orLater(defJSON.Operators),
		ValidatorAddresses: repeatVAddrs(vaddrs, defJSON.NumValidators),
		Creator: Creator{
			Address:         defJSON.Creator.Address,
			ConfigSignature: defJSON.Creator.ConfigSignature,
		},
	}, nil
}

func unmarshalDefinitionV1x5to7(data []byte) (def Definition, err error) {
	var defJSON definitionJSONv1x5
	if err := json.Unmarshal(data, &defJSON); err != nil {
		return Definition{}, errors.Wrap(err, "unmarshal definition v1_5")
	}

	if len(defJSON.ValidatorAddresses) != defJSON.NumValidators {
		return Definition{}, errors.New("num_validators not matching validators length")
	}

	return Definition{
		Name:               defJSON.Name,
		UUID:               defJSON.UUID,
		Version:            defJSON.Version,
		Timestamp:          defJSON.Timestamp,
		NumValidators:      defJSON.NumValidators,
		Threshold:          defJSON.Threshold,
		DKGAlgorithm:       defJSON.DKGAlgorithm,
		ForkVersion:        defJSON.ForkVersion,
		ConfigHash:         defJSON.ConfigHash,
		DefinitionHash:     defJSON.DefinitionHash,
		Operators:          operatorsFromV1x2orLater(defJSON.Operators),
		ValidatorAddresses: validatorAddressesFromJSON(defJSON.ValidatorAddresses),
		Creator: Creator{
			Address:         defJSON.Creator.Address,
			ConfigSignature: defJSON.Creator.ConfigSignature,
		},
	}, nil
}

func unmarshalDefinitionV1x8(data []byte) (def Definition, err error) {
	var defJSON definitionJSONv1x8
	if err := json.Unmarshal(data, &defJSON); err != nil {
		return Definition{}, errors.Wrap(err, "unmarshal definition v1_8")
	}

	if len(defJSON.ValidatorAddresses) != defJSON.NumValidators {
		return Definition{}, errors.New("num_validators not matching validators length")
	}

	return Definition{
		Name:               defJSON.Name,
		UUID:               defJSON.UUID,
		Version:            defJSON.Version,
		Timestamp:          defJSON.Timestamp,
		NumValidators:      defJSON.NumValidators,
		Threshold:          defJSON.Threshold,
		DKGAlgorithm:       defJSON.DKGAlgorithm,
		ForkVersion:        defJSON.ForkVersion,
		ConfigHash:         defJSON.ConfigHash,
		DefinitionHash:     defJSON.DefinitionHash,
		Operators:          operatorsFromV1x2orLater(defJSON.Operators),
		ValidatorAddresses: validatorAddressesFromJSON(defJSON.ValidatorAddresses),
		Creator: Creator{
			Address:         defJSON.Creator.Address,
			ConfigSignature: defJSON.Creator.ConfigSignature,
		},
		DepositAmounts: defJSON.DepositAmounts,
	}, nil
}

// supportEIP712Sigs returns true if the provided definition version supports EIP712 signatures.
// Note that Definition versions prior to v1.3.0 don't support EIP712 signatures.
func supportEIP712Sigs(version string) bool {
	return !isAnyVersion(version, v1_0, v1_1, v1_2)
}

func eip712SigsPresent(operators []Operator) bool {
	for _, o := range operators {
		if len(o.ENRSignature) > 0 || len(o.ConfigSignature) > 0 {
			return true
		}
	}

	return false
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
	Name                string                    `json:"name,omitempty"`
	Operators           []operatorJSONv1x2orLater `json:"operators"`
	UUID                string                    `json:"uuid"`
	Version             string                    `json:"version"`
	Timestamp           string                    `json:"timestamp,omitempty"`
	NumValidators       int                       `json:"num_validators"`
	Threshold           int                       `json:"threshold"`
	FeeRecipientAddress string                    `json:"fee_recipient_address,omitempty"`
	WithdrawalAddress   string                    `json:"withdrawal_address,omitempty"`
	DKGAlgorithm        string                    `json:"dkg_algorithm"`
	ForkVersion         ethHex                    `json:"fork_version"`
	ConfigHash          ethHex                    `json:"config_hash"`
	DefinitionHash      ethHex                    `json:"definition_hash"`
}

// definitionJSONv1x4 is the json formatter of Definition for version v1.4.
type definitionJSONv1x4 struct {
	Name                string                    `json:"name,omitempty"`
	Creator             creatorJSON               `json:"creator"`
	Operators           []operatorJSONv1x2orLater `json:"operators"`
	UUID                string                    `json:"uuid"`
	Version             string                    `json:"version"`
	Timestamp           string                    `json:"timestamp,omitempty"`
	NumValidators       int                       `json:"num_validators"`
	Threshold           int                       `json:"threshold"`
	FeeRecipientAddress string                    `json:"fee_recipient_address,omitempty"`
	WithdrawalAddress   string                    `json:"withdrawal_address,omitempty"`
	DKGAlgorithm        string                    `json:"dkg_algorithm"`
	ForkVersion         ethHex                    `json:"fork_version"`
	ConfigHash          ethHex                    `json:"config_hash"`
	DefinitionHash      ethHex                    `json:"definition_hash"`
}

// definitionJSONv1x5 is the json formatter of Definition for versions v1.5 to v1.7.
type definitionJSONv1x5 struct {
	Name               string                    `json:"name,omitempty"`
	Creator            creatorJSON               `json:"creator"`
	Operators          []operatorJSONv1x2orLater `json:"operators"`
	UUID               string                    `json:"uuid"`
	Version            string                    `json:"version"`
	Timestamp          string                    `json:"timestamp,omitempty"`
	NumValidators      int                       `json:"num_validators"`
	Threshold          int                       `json:"threshold"`
	ValidatorAddresses []validatorAddressesJSON  `json:"validators"`
	DKGAlgorithm       string                    `json:"dkg_algorithm"`
	ForkVersion        ethHex                    `json:"fork_version"`
	ConfigHash         ethHex                    `json:"config_hash"`
	DefinitionHash     ethHex                    `json:"definition_hash"`
}

// definitionJSONv1x8 is the json formatter of Definition for versions v1.8 or later.
type definitionJSONv1x8 struct {
	Name               string                    `json:"name,omitempty"`
	Creator            creatorJSON               `json:"creator"`
	Operators          []operatorJSONv1x2orLater `json:"operators"`
	UUID               string                    `json:"uuid"`
	Version            string                    `json:"version"`
	Timestamp          string                    `json:"timestamp,omitempty"`
	NumValidators      int                       `json:"num_validators"`
	Threshold          int                       `json:"threshold"`
	ValidatorAddresses []validatorAddressesJSON  `json:"validators"`
	DKGAlgorithm       string                    `json:"dkg_algorithm"`
	ForkVersion        ethHex                    `json:"fork_version"`
	DepositAmounts     []eth2p0.Gwei             `json:"deposit_amounts"`
	ConfigHash         ethHex                    `json:"config_hash"`
	DefinitionHash     ethHex                    `json:"definition_hash"`
}

// Creator identifies the creator of a cluster definition.
// Note the following struct tag meanings:
//   - json: json field name. Suffix 0xhex indicates bytes are formatted as 0x prefixed hex strings.
//   - ssz: ssz equivalent. Either uint64 for numbers, BytesN for fixed length bytes, ByteList[MaxN]
//     for variable length strings, or CompositeList[MaxN] for nested object arrays.
//   - config_hash: field ordering when calculating config hash. Some fields are excluded indicated by `-`.
//   - definition_hash: field ordering when calculating definition hash. Some fields are excluded indicated by `-`.
type Creator struct {
	// The 20 byte Ethereum address of the creator
	Address string `json:"address,0xhex" ssz:"Bytes20" config_hash:"0" definition_hash:"0"`

	// ConfigSignature is an EIP712 signature of the config_hash using privkey corresponding to creator Ethereum Address.
	ConfigSignature []byte `json:"config_signature,0xhex" ssz:"Bytes65" config_hash:"-" definition_hash:"1"`
}

// creatorJSON is the json formatter of Creator.
type creatorJSON struct {
	Address         string `json:"address"`
	ConfigSignature ethHex `json:"config_signature"`
}

// ValidatorAddresses defines addresses of a validator.
type ValidatorAddresses struct {
	// FeeRecipientAddress 20 byte Ethereum address.
	FeeRecipientAddress string `json:"fee_recipient_address,0xhex" ssz:"Bytes20" config_hash:"0" definition_hash:"0"`

	// WithdrawalAddress 20 byte Ethereum address.
	WithdrawalAddress string `json:"withdrawal_address,0xhex" ssz:"Bytes20" config_hash:"1" definition_hash:"1"`
}

// validatorAddressesJSON is the json formatter of ValidatorAddresses.
type validatorAddressesJSON struct {
	FeeRecipientAddress string `json:"fee_recipient_address"`
	WithdrawalAddress   string `json:"withdrawal_address"`
}

// validatorAddressesToJSON returns the json formatters for the slice of ValidatorAddresses.
func validatorAddressesToJSON(vaddrs []ValidatorAddresses) []validatorAddressesJSON {
	var resp []validatorAddressesJSON
	for _, vaddr := range vaddrs {
		resp = append(resp, validatorAddressesJSON(vaddr))
	}

	return resp
}

// validatorAddressesFromJSON returns a slice of ValidatorAddresses from the json formatters.
func validatorAddressesFromJSON(vaddrs []validatorAddressesJSON) []ValidatorAddresses {
	var resp []ValidatorAddresses
	for _, vaddr := range vaddrs {
		resp = append(resp, ValidatorAddresses(vaddr))
	}

	return resp
}

// repeatVAddrs returns a slice of n identical ValidatorAddresses.
func repeatVAddrs(addr ValidatorAddresses, n int) []ValidatorAddresses {
	var resp []ValidatorAddresses
	for i := 0; i < n; i++ {
		resp = append(resp, addr)
	}

	return resp
}
