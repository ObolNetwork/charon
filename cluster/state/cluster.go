// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
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
	for _, vaddrs := range c.Validators {
		resp = append(resp, vaddrs.WithdrawalAddress)
	}

	return resp
}

// FeeRecipientAddresses is a convenience function to return all fee-recipient address from the validators slice.
func (c Cluster) FeeRecipientAddresses() []string {
	var resp []string
	for _, vaddrs := range c.Validators {
		resp = append(resp, vaddrs.FeeRecipientAddress)
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
	Address string
	ENR     string
}

// Validator represents a validator in the cluster.
type Validator struct {
	PubKey              []byte
	PubShares           [][]byte
	FeeRecipientAddress string
	WithdrawalAddress   string
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
