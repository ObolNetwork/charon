// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	"bytes"
	"encoding/json"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/eth2util/registration"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// Lock extends the cluster config Definition with bls threshold public keys and checksums.
type Lock struct {
	// Definition is embedded and extended by Lock.
	Definition `json:"cluster_definition" lock_hash:"0" ssz:"Composite"`

	// Validators are the distributed validators (n*32ETH) managed by the cluster.
	Validators []DistValidator `json:"distributed_validators" lock_hash:"1" ssz:"Composite[65536]"`

	// LockHash uniquely identifies a cluster lock.
	LockHash []byte `json:"lock_hash" lock_hash:"-" ssz:"Bytes32"`

	// SignatureAggregate is the bls aggregate signature of the lock hash signed by
	// all the private key shares of all the distributed validators.
	// It acts as an attestation by all the distributed validators
	// of the charon cluster they are part of.
	SignatureAggregate []byte `json:"signature_aggregate" lock_hash:"-" ssz:"Bytes96"`

	// NodeSignatures contains a signature of the lock hash for each operator defined in the Definition.
	NodeSignatures [][]byte `json:"node_signatures" lock_hash:"-" ssz:"Composite"`
}

func (l Lock) MarshalJSON() ([]byte, error) {
	// Marshal lock hash
	lockHash, err := hashLock(l)
	if err != nil {
		return nil, errors.Wrap(err, "hash lock")
	}

	switch {
	case isAnyVersion(l.Version, v1_0, v1_1):
		return marshalLockV1x0or1(l, lockHash)
	case isAnyVersion(l.Version, v1_2, v1_3, v1_4, v1_5):
		return marshalLockV1x2to5(l, lockHash)
	case isAnyVersion(l.Version, v1_6):
		return marshalLockV1x6(l, lockHash)
	case isAnyVersion(l.Version, v1_7):
		return marshalLockV1x7(l, lockHash)
	case isAnyVersion(l.Version, v1_8):
		return marshalLockV1x8OrLater(l, lockHash)
	default:
		return nil, errors.New("unsupported version")
	}
}

func (l *Lock) UnmarshalJSON(data []byte) error {
	// Get the version directly
	version := struct {
		Definition struct {
			Version string `json:"version"`
		} `json:"cluster_definition"`
	}{}
	if err := json.Unmarshal(data, &version); err != nil {
		return errors.Wrap(err, "unmarshal version")
	} else if !supportedVersions[version.Definition.Version] {
		return errors.New("unsupported definition version",
			z.Str("version", version.Definition.Version),
			z.Any("supported", supportedVersions),
		)
	}

	var (
		lock Lock
		err  error
	)
	switch {
	case isAnyVersion(version.Definition.Version, v1_0, v1_1):
		lock, err = unmarshalLockV1x0or1(data)
		if err != nil {
			return err
		}
	case isAnyVersion(version.Definition.Version, v1_2, v1_3, v1_4, v1_5):
		lock, err = unmarshalLockV1x2to5(data)
		if err != nil {
			return err
		}
	case isAnyVersion(version.Definition.Version, v1_6):
		lock, err = unmarshalLockV1x6(data)
		if err != nil {
			return err
		}
	case isAnyVersion(version.Definition.Version, v1_7):
		lock, err = unmarshalLockV1x7(data)
		if err != nil {
			return err
		}
	case isAnyVersion(version.Definition.Version, v1_8):
		lock, err = unmarshalLockV1x8OrLater(data)
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported version")
	}

	*l = lock

	return nil
}

// SetLockHash returns a copy of the lock with the lock hash populated.
func (l Lock) SetLockHash() (Lock, error) {
	lockHash, err := hashLock(l)
	if err != nil {
		return Lock{}, err
	}

	l.LockHash = lockHash[:]

	return l, nil
}

// VerifyHashes returns an error if hashes populated from json object doesn't matches actual hashes.
func (l Lock) VerifyHashes() error {
	if err := l.Definition.VerifyHashes(); err != nil {
		return errors.Wrap(err, "invalid definition")
	}

	lockHash, err := hashLock(l)
	if err != nil {
		return err
	}

	if !bytes.Equal(l.LockHash, lockHash[:]) {
		return errors.New("invalid lock hash")
	}

	return nil
}

// VerifySignatures returns true if all config signatures are fully populated and valid.
// A verified lock is ready for use in charon run.
func (l Lock) VerifySignatures() error {
	if err := l.Definition.VerifySignatures(); err != nil {
		return errors.Wrap(err, "invalid definition")
	}

	if len(l.SignatureAggregate) == 0 {
		if isAnyVersion(l.Version, v1_0, v1_1) {
			return nil // Earlier versions of `charon create cluster` didn't populate SignatureAggregate.
		}

		return errors.New("empty lock aggregate signature")
	}

	sig, err := tblsconv.SignatureFromBytes(l.SignatureAggregate)
	if err != nil {
		return err
	}

	var pubkeys []tbls.PublicKey
	for _, val := range l.Validators {
		for _, share := range val.PubShares {
			pubkey, err := tblsconv.PubkeyFromBytes(share)
			if err != nil {
				return err
			}
			pubkeys = append(pubkeys, pubkey)
		}
	}

	hash, err := hashLock(l)
	if err != nil {
		return err
	}

	err = tbls.VerifyAggregate(pubkeys, sig, hash[:])
	if err != nil {
		return errors.Wrap(err, "verify lock signature aggregate")
	}

	err = l.verifyBuilderRegistrations()
	if err != nil {
		return errors.Wrap(err, "verify pre-generated builder registrations")
	}

	return l.verifyNodeSignatures()
}

// verifyNodeSignatures returns true an error if the node signatures field is not correctly
// populated or otherwise invalid.
func (l Lock) verifyNodeSignatures() error {
	if isAnyVersion(l.Version, v1_0, v1_1, v1_2, v1_3, v1_4, v1_5, v1_6) {
		if len(l.NodeSignatures) > 0 {
			return errors.New("unexpected node signatures")
		}

		return nil
	}

	// Ensure correct count of node signatures.
	if len(l.NodeSignatures) != len(l.Operators) {
		return errors.New("invalid node signature count")
	}

	// Verify the node signatures
	for idx := 0; idx < len(l.Operators); idx++ {
		record, err := enr.Parse(l.Operators[idx].ENR)
		if err != nil {
			return errors.Wrap(err, "operator ENR")
		}

		verified, err := k1util.Verify65(record.PubKey, l.LockHash, l.NodeSignatures[idx])
		if err != nil {
			return errors.Wrap(err, "node signature check")
		} else if !verified {
			return errors.New("node signature verification failed",
				z.Int("peer_index", idx),
			)
		}
	}

	return nil
}

// verifyBuilderRegistrations returns an error if the populated builder registrations are invalid.
func (l Lock) verifyBuilderRegistrations() error {
	feeRecipientAddrs := l.FeeRecipientAddresses()
	for i, val := range l.Validators {
		noRegistration := len(val.BuilderRegistration.Signature) == 0 ||
			len(val.BuilderRegistration.Message.FeeRecipient) == 0 ||
			len(val.BuilderRegistration.Message.PubKey) == 0

		if isAnyVersion(l.Version, v1_0, v1_1, v1_2, v1_3, v1_4, v1_5, v1_6) {
			if !noRegistration {
				return errors.New("unexpected validator registration")
			}

			continue
		}

		if noRegistration {
			return errors.New("missing validator registration", z.Int("i", i))
		}

		regMsg, err := registration.NewMessage(eth2p0.BLSPubKey(val.PubKey), feeRecipientAddrs[i], uint64(val.BuilderRegistration.Message.GasLimit), val.BuilderRegistration.Message.Timestamp)
		if err != nil {
			return err
		}

		sigRoot, err := registration.GetMessageSigningRoot(regMsg, eth2p0.Version(l.ForkVersion))
		if err != nil {
			return err
		}

		pubkey, err := tblsconv.PubkeyFromBytes(val.PubKey)
		if err != nil {
			return errors.Wrap(err, "core pubkey from bytes")
		}

		sig, err := tblsconv.SignatureFromBytes(val.BuilderRegistration.Signature)
		if err != nil {
			return errors.Wrap(err, "tbls signature from bytes")
		}

		err = tbls.Verify(pubkey, sigRoot[:], sig)
		if err != nil {
			return errors.Wrap(err, "verify builder registration signature")
		}
	}

	return nil
}

func marshalLockV1x0or1(lock Lock, lockHash [32]byte) ([]byte, error) {
	resp, err := json.Marshal(lockJSONv1x0or1{
		Definition:         lock.Definition,
		Validators:         distValidatorsToV1x1(lock.Validators),
		SignatureAggregate: lock.SignatureAggregate,
		LockHash:           lockHash[:],
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal definition v1_1")
	}

	return resp, nil
}

func marshalLockV1x2to5(lock Lock, lockHash [32]byte) ([]byte, error) {
	resp, err := json.Marshal(lockJSONv1x2to5{
		Definition:         lock.Definition,
		Validators:         distValidatorsToV1x2to5(lock.Validators),
		SignatureAggregate: lock.SignatureAggregate,
		LockHash:           lockHash[:],
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal definition v1_2-5")
	}

	return resp, nil
}

func marshalLockV1x6(lock Lock, lockHash [32]byte) ([]byte, error) {
	resp, err := json.Marshal(lockJSONv1x6{
		Definition:         lock.Definition,
		Validators:         distValidatorsToV1x6(lock.Validators),
		SignatureAggregate: lock.SignatureAggregate,
		LockHash:           lockHash[:],
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal definition v1_6")
	}

	return resp, nil
}

func marshalLockV1x7(lock Lock, lockHash [32]byte) ([]byte, error) {
	resp, err := json.Marshal(lockJSONv1x7{
		Definition:         lock.Definition,
		Validators:         distValidatorsToV1x7(lock.Validators),
		SignatureAggregate: lock.SignatureAggregate,
		LockHash:           lockHash[:],
		NodeSignatures:     byteSliceArrayToEthHex(lock.NodeSignatures),
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal definition v1_7")
	}

	return resp, nil
}

func marshalLockV1x8OrLater(lock Lock, lockHash [32]byte) ([]byte, error) {
	resp, err := json.Marshal(lockJSONv1x8{
		Definition:         lock.Definition,
		Validators:         distValidatorsToV1x8OrLater(lock.Validators),
		SignatureAggregate: lock.SignatureAggregate,
		LockHash:           lockHash[:],
		NodeSignatures:     byteSliceArrayToEthHex(lock.NodeSignatures),
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal definition v1_8")
	}

	return resp, nil
}

func unmarshalLockV1x0or1(data []byte) (lock Lock, err error) {
	var lockJSON lockJSONv1x0or1
	if err := json.Unmarshal(data, &lockJSON); err != nil {
		return Lock{}, errors.Wrap(err, "unmarshal definition")
	}

	for _, validator := range lockJSON.Validators {
		if len(validator.FeeRecipientAddress) > 0 {
			return Lock{}, errors.New("distributed validator fee recipient not supported anymore")
		}
	}

	lock = Lock{
		Definition:         lockJSON.Definition,
		Validators:         distValidatorsFromV1x1(lockJSON.Validators),
		SignatureAggregate: lockJSON.SignatureAggregate,
		LockHash:           lockJSON.LockHash,
	}

	return lock, nil
}

func unmarshalLockV1x2to5(data []byte) (lock Lock, err error) {
	var lockJSON lockJSONv1x2to5
	if err := json.Unmarshal(data, &lockJSON); err != nil {
		return Lock{}, errors.Wrap(err, "unmarshal definition")
	}

	for _, validator := range lockJSON.Validators {
		if len(validator.FeeRecipientAddress) > 0 {
			return Lock{}, errors.New("distributed validator fee recipient not supported anymore")
		}
	}

	lock = Lock{
		Definition:         lockJSON.Definition,
		Validators:         distValidatorsFromV1x2to5(lockJSON.Validators),
		SignatureAggregate: lockJSON.SignatureAggregate,
		LockHash:           lockJSON.LockHash,
	}

	return lock, nil
}

func unmarshalLockV1x6(data []byte) (lock Lock, err error) {
	var lockJSON lockJSONv1x6
	if err := json.Unmarshal(data, &lockJSON); err != nil {
		return Lock{}, errors.Wrap(err, "unmarshal definition")
	}

	lock = Lock{
		Definition:         lockJSON.Definition,
		Validators:         distValidatorsFromV1x6(lockJSON.Validators),
		SignatureAggregate: lockJSON.SignatureAggregate,
		LockHash:           lockJSON.LockHash,
	}

	return lock, nil
}

func unmarshalLockV1x7(data []byte) (lock Lock, err error) {
	var lockJSON lockJSONv1x7
	if err := json.Unmarshal(data, &lockJSON); err != nil {
		return Lock{}, errors.Wrap(err, "unmarshal definition")
	}

	var nodeSignatures [][]byte
	for _, ns := range lockJSON.NodeSignatures {
		nodeSignatures = append(nodeSignatures, ns)
	}

	lock = Lock{
		Definition:         lockJSON.Definition,
		Validators:         distValidatorsFromV1x7(lockJSON.Validators),
		SignatureAggregate: lockJSON.SignatureAggregate,
		LockHash:           lockJSON.LockHash,
		NodeSignatures:     nodeSignatures,
	}

	return lock, nil
}

func unmarshalLockV1x8OrLater(data []byte) (lock Lock, err error) {
	var lockJSON lockJSONv1x8
	if err := json.Unmarshal(data, &lockJSON); err != nil {
		return Lock{}, errors.Wrap(err, "unmarshal definition")
	}

	var nodeSignatures [][]byte
	for _, ns := range lockJSON.NodeSignatures {
		nodeSignatures = append(nodeSignatures, ns)
	}

	lock = Lock{
		Definition:         lockJSON.Definition,
		Validators:         distValidatorsFromV1x8OrLater(lockJSON.Validators),
		SignatureAggregate: lockJSON.SignatureAggregate,
		LockHash:           lockJSON.LockHash,
		NodeSignatures:     nodeSignatures,
	}

	return lock, nil
}

// lockJSONv1x0or1 is the json formatter of Lock for versions v1.0.0 and v1.1.0.
type lockJSONv1x0or1 struct {
	Definition         Definition              `json:"cluster_definition"`
	Validators         []distValidatorJSONv1x1 `json:"distributed_validators"`
	SignatureAggregate []byte                  `json:"signature_aggregate"`
	LockHash           []byte                  `json:"lock_hash"`
}

// lockJSONv1x2to5 is the json formatter of Lock for versions v1.2.0 to v1.5.0.
type lockJSONv1x2to5 struct {
	Definition         Definition                 `json:"cluster_definition"`
	Validators         []distValidatorJSONv1x2to5 `json:"distributed_validators"`
	SignatureAggregate ethHex                     `json:"signature_aggregate"`
	LockHash           ethHex                     `json:"lock_hash"`
}

// lockJSONv1x6 is the json formatter of Lock for version v1.6.0.
type lockJSONv1x6 struct {
	Definition         Definition              `json:"cluster_definition"`
	Validators         []distValidatorJSONv1x6 `json:"distributed_validators"`
	SignatureAggregate ethHex                  `json:"signature_aggregate"`
	LockHash           ethHex                  `json:"lock_hash"`
}

// lockJSONv1x7 is the json formatter of Lock for version v1.7.0.
type lockJSONv1x7 struct {
	Definition         Definition              `json:"cluster_definition"`
	Validators         []distValidatorJSONv1x7 `json:"distributed_validators"`
	SignatureAggregate ethHex                  `json:"signature_aggregate"`
	LockHash           ethHex                  `json:"lock_hash"`
	NodeSignatures     []ethHex                `json:"node_signatures"`
}

// lockJSONv1x8 is the json formatter of Lock for versions v1.8.0 or later.
type lockJSONv1x8 struct {
	Definition         Definition              `json:"cluster_definition"`
	Validators         []distValidatorJSONv1x8 `json:"distributed_validators"`
	SignatureAggregate ethHex                  `json:"signature_aggregate"`
	LockHash           ethHex                  `json:"lock_hash"`
	NodeSignatures     []ethHex                `json:"node_signatures"`
}
