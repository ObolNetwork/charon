// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package manifest

import (
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// ClusterPeers returns the cluster operators as a slice of p2p peers.
func ClusterPeers(c *manifestpb.Cluster) ([]p2p.Peer, error) {
	if c == nil || len(c.Operators) == 0 {
		return nil, errors.New("invalid cluster")
	}

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

// ClusterPeerIDs is a convenience function that returns the operators p2p peer IDs.
func ClusterPeerIDs(c *manifestpb.Cluster) ([]peer.ID, error) {
	peers, err := ClusterPeers(c)
	if err != nil {
		return nil, err
	}
	var resp []peer.ID
	for _, p := range peers {
		resp = append(resp, p.ID)
	}

	return resp, nil
}

// ClusterNodeIdx returns the node index for the peer in the cluster.
func ClusterNodeIdx(c *manifestpb.Cluster, pID peer.ID) (cluster.NodeIdx, error) {
	peers, err := ClusterPeers(c)
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

// ValidatorPublicKey returns the validator BLS group public key.
func ValidatorPublicKey(v *manifestpb.Validator) (tbls.PublicKey, error) {
	return tblsconv.PubkeyFromBytes(v.PublicKey)
}

// ValidatorPublicKeyHex returns the validator hex group public key.
func ValidatorPublicKeyHex(v *manifestpb.Validator) string {
	return to0xHex(v.PublicKey)
}

// ValidatorPublicShare returns the validator's peerIdx'th BLS public share.
func ValidatorPublicShare(v *manifestpb.Validator, peerIdx int) (tbls.PublicKey, error) {
	return tblsconv.PubkeyFromBytes(v.PubShares[peerIdx])
}
