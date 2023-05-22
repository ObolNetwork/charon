// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// Cluster represents the state of a cluster after applying a sequence of mutations.
type Cluster struct {
	Hash         [32]byte
	Name         string
	Threshold    int
	DKGAlgorithm string
	ForkVersion  []byte
	Operators    []Operator
	Validators   []Validator
}

// Peers returns the operators as a slice of p2p peers.
func (c Cluster) Peers() ([]p2p.Peer, error) {
	var resp []p2p.Peer
	for i, operator := range c.Operators {
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
func (c Cluster) PeerIDs() ([]peer.ID, error) {
	peers, err := c.Peers()
	if err != nil {
		return nil, err
	}
	var resp []peer.ID
	for _, p := range peers {
		resp = append(resp, p.ID)
	}

	return resp, nil
}

// WithdrawalAddresses is a convenience function to return all withdrawal address from the validators slice.
func (c Cluster) WithdrawalAddresses() []string {
	var resp []string
	for _, val := range c.Validators {
		resp = append(resp, val.WithdrawalAddress)
	}

	return resp
}

// FeeRecipientAddresses is a convenience function that returns fee-recipient addresses for all the validators in the cluster state.
func (c Cluster) FeeRecipientAddresses() []string {
	var resp []string
	for _, val := range c.Validators {
		resp = append(resp, val.FeeRecipientAddress)
	}

	return resp
}

// NodeIdx returns the node index for the peer.
func (c Cluster) NodeIdx(pID peer.ID) (cluster.NodeIdx, error) {
	peers, err := c.Peers()
	if err != nil {
		return cluster.NodeIdx{}, err
	}

	for i, p := range peers {
		if p.ID != pID {
			continue
		}

		return cluster.NodeIdx{
			PeerIdx:  i,     // 0-indexed
			ShareIdx: i + 1, // 1-indexed
		}, nil
	}

	return cluster.NodeIdx{}, errors.New("peer not in definition")
}

// Operator represents the operator of a node in the cluster.
type Operator struct {
	Address string `json:"address"`
	ENR     string `json:"enr"`
}

// Validator represents a validator in the cluster.
type Validator struct {
	PubKey              []byte              `json:"public_key"`
	PubShares           [][]byte            `json:"public_shares"`
	FeeRecipientAddress string              `json:"fee_recipient_address"`
	WithdrawalAddress   string              `json:"withdrawal_address"`
	BuilderRegistration BuilderRegistration `json:"builder_registration"`
}

// PublicKey returns the validator BLS group public key.
func (v Validator) PublicKey() (tbls.PublicKey, error) {
	return tblsconv.PubkeyFromBytes(v.PubKey)
}

// PublicKeyHex returns the validator hex group public key.
func (v Validator) PublicKeyHex() string {
	return to0xHex(v.PubKey)
}

// PublicShare returns a peer's threshold BLS public share.
func (v Validator) PublicShare(peerIdx int) (tbls.PublicKey, error) {
	return tblsconv.PubkeyFromBytes(v.PubShares[peerIdx])
}

// toSSZ returns a SSZ friendly version of the validator.
func (v Validator) toSSZ() validatorSSZ {
	var pubshares []sszPubkey
	for _, share := range v.PubShares {
		pubshares = append(pubshares, sszPubkey{Pubkey: share})
	}

	// Convert to bytes ignoring errors, assume that verify has been called.
	// TODO(corver): Extend genssz to handle errors in transform functions.
	feeRecipient, _ := from0xHex(v.FeeRecipientAddress, 20)
	withdrawal, _ := from0xHex(v.WithdrawalAddress, 20)

	return validatorSSZ{
		PubKey:              v.PubKey,
		PubShares:           pubshares,
		FeeRecipientAddress: feeRecipient,
		WithdrawalAddress:   withdrawal,
	}
}

type validatorJSON struct {
	PubKey              ethHex                  `json:"public_key"`
	PubShares           []ethHex                `json:"public_shares"`
	FeeRecipientAddress string                  `json:"fee_recipient_address"`
	WithdrawalAddress   string                  `json:"withdrawal_address"`
	BuilderRegistration builderRegistrationJSON `json:"builder_registration"`
}

func validatorsToJSON(vals []Validator) []validatorJSON {
	var resp []validatorJSON
	for _, val := range vals {
		var pubshares []ethHex
		for _, share := range val.PubShares {
			pubshares = append(pubshares, share)
		}

		resp = append(resp, validatorJSON{
			PubKey:              val.PubKey,
			PubShares:           pubshares,
			FeeRecipientAddress: val.FeeRecipientAddress,
			WithdrawalAddress:   val.WithdrawalAddress,
			BuilderRegistration: registrationToJSON(val.BuilderRegistration),
		})
	}

	return resp
}

func validatorsFromJSON(vals []validatorJSON) ([]Validator, error) {
	var resp []Validator
	for _, val := range vals {
		var pubshares [][]byte
		for _, share := range val.PubShares {
			pubshares = append(pubshares, share)
		}

		reg, err := registrationFromJSON(val.BuilderRegistration)
		if err != nil {
			return nil, errors.Wrap(err, "validator registration from json")
		}

		resp = append(resp, Validator{
			PubKey:              val.PubKey,
			PubShares:           pubshares,
			FeeRecipientAddress: val.FeeRecipientAddress,
			WithdrawalAddress:   val.WithdrawalAddress,
			BuilderRegistration: reg,
		})
	}

	return resp, nil
}

type validatorSSZ struct {
	PubKey              []byte      `ssz:"ByteList[256]"`
	PubShares           []sszPubkey `ssz:"CompositeList[65536]"`
	FeeRecipientAddress []byte      `ssz:"Bytes20"`
	WithdrawalAddress   []byte      `ssz:"Bytes20"`
}

type sszPubkey struct {
	Pubkey []byte `ssz:"ByteList[256]"`
}

// BuilderRegistration defines pre-generated signed validator builder registration to be sent to builder network.
type BuilderRegistration struct {
	Message   Registration `json:"message" ssz:"Composite" lock_hash:"0"`
	Signature []byte       `json:"signature" ssz:"Bytes96" lock_hash:"1"`
}

// Registration defines unsigned validator registration message.
type Registration struct {
	FeeRecipient []byte    `json:"fee_recipient"  ssz:"Bytes20"`
	GasLimit     int       `json:"gas_limit"  ssz:"uint64"`
	Timestamp    time.Time `json:"timestamp"  ssz:"uint64,Unix"`
	PubKey       []byte    `json:"pubkey"  ssz:"Bytes48"`
}

// builderRegistrationJSON is the json formatter of BuilderRegistration.
type builderRegistrationJSON struct {
	Message   registrationJSON `json:"message"`
	Signature ethHex           `json:"signature"`
}

// registrationJSON is the json formatter of Registration.
type registrationJSON struct {
	FeeRecipient ethHex `json:"fee_recipient"`
	GasLimit     int    `json:"gas_limit"`
	Timestamp    string `json:"timestamp"`
	PubKey       ethHex `json:"pubkey"`
}

// registrationToJSON converts BuilderRegistration to builderRegistrationJSON.
func registrationToJSON(b BuilderRegistration) builderRegistrationJSON {
	return builderRegistrationJSON{
		Message: registrationJSON{
			FeeRecipient: b.Message.FeeRecipient,
			GasLimit:     b.Message.GasLimit,
			Timestamp:    b.Message.Timestamp.Format(time.RFC3339),
			PubKey:       b.Message.PubKey,
		},
		Signature: b.Signature,
	}
}

// registrationFromJSON converts registrationFromJSON to BuilderRegistration.
func registrationFromJSON(b builderRegistrationJSON) (BuilderRegistration, error) {
	timestamp, err := time.Parse(time.RFC3339, b.Message.Timestamp)
	if err != nil {
		return BuilderRegistration{}, errors.Wrap(err, "parse timestamp")
	}

	return BuilderRegistration{
		Message: Registration{
			FeeRecipient: b.Message.FeeRecipient,
			GasLimit:     b.Message.GasLimit,
			Timestamp:    timestamp,
			PubKey:       b.Message.PubKey,
		},
		Signature: b.Signature,
	}, nil
}
