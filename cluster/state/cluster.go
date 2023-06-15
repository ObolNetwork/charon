// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	pbv1 "github.com/obolnetwork/charon/cluster/statepb/v1"
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
	Operators    []*pbv1.Operator
	Validators   []*pbv1.Validator
}

// Peers returns the operators as a slice of p2p peers.
func (c Cluster) Peers() ([]p2p.Peer, error) {
	var resp []p2p.Peer
	dedup := make(map[string]bool)
	for i, operator := range c.Operators {
		if dedup[operator.Enr] {
			return nil, errors.New("cluster contains duplicate peer enrs", z.Str("enr", operator.Enr))
		}
		dedup[operator.Enr] = true

		record, err := enr.Parse(operator.Enr)
		if err != nil {
			return nil, errors.Wrap(err, "decode enr", z.Str("enr", operator.Enr))
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

// ValidatorPublicKey returns the valIdx'th validator BLS group public key.
func (c Cluster) ValidatorPublicKey(valIdx int) (tbls.PublicKey, error) {
	return tblsconv.PubkeyFromBytes(c.Validators[valIdx].PublicKey)
}

// ValidatorPublicKeyHex returns the valIdx'th validator hex group public key.
func (c Cluster) ValidatorPublicKeyHex(valIdx int) string {
	return to0xHex(c.Validators[valIdx].PublicKey)
}

// ValidatorPublicShare returns the valIdx'th validator's peerIdx'th BLS public share.
func (c Cluster) ValidatorPublicShare(valIdx int, peerIdx int) (tbls.PublicKey, error) {
	return tblsconv.PubkeyFromBytes(c.Validators[valIdx].PubShares[peerIdx])
}
