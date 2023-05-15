// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	"bytes"
	"encoding/json"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

// SignNodeApproval signs a node approval mutation.
func SignNodeApproval(parent [32]byte, secret *k1.PrivateKey) (SignedMutation, error) {
	return SignK1(Mutation{
		Parent:    parent,
		Type:      TypeNodeApproval,
		Timestamp: nowFunc(),
		Data:      emptyData{},
	}, secret)
}

type nodeApprovals struct {
	Approvals []SignedMutation `ssz:"CompositeList[256]"`
}

func (n nodeApprovals) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(n.Approvals)
	if err != nil {
		return nil, errors.Wrap(err, "marshal node approvals")
	}

	return b, nil
}

// NewNodeApprovalsComposite returns a new composite node approvals mutation.
// Note the approvals must be for all nodes in the cluster ordered by peer index.
func NewNodeApprovalsComposite(approvals []SignedMutation) (SignedMutation, error) {
	if len(approvals) == 0 {
		return SignedMutation{}, errors.New("empty node approvals")
	}

	var parent [32]byte
	for i, approval := range approvals {
		if i == 0 {
			parent = approval.Mutation.Parent
		} else if parent != approval.Mutation.Parent {
			return SignedMutation{}, errors.New("mismatching node approvals parent")
		}

		if err := verifyNodeApproval(approval); err != nil {
			return SignedMutation{}, errors.Wrap(err, "verify node approval", z.Int("index", i))
		}
	}

	return SignedMutation{
		Mutation: Mutation{
			Parent:    parent,
			Type:      TypeNodeApprovals,
			Timestamp: nowFunc(),
			Data: nodeApprovals{
				Approvals: approvals,
			},
		},
		// Composite types do not have signatures
	}, nil
}

// verifyNodeApproval returns an error if the .
func verifyNodeApproval(signed SignedMutation) error {
	if signed.Mutation.Type != TypeNodeApproval {
		return errors.New("invalid mutation type")
	}

	if _, ok := signed.Mutation.Data.(emptyData); !ok {
		return errors.New("invalid node approval data")
	}

	return verifyK1SignedMutation(signed)
}

// transformNodeApprovals transforms the cluster state with the node approvals.
func transformNodeApprovals(c Cluster, signed SignedMutation) (Cluster, error) {
	if signed.Mutation.Type != TypeNodeApprovals {
		return c, errors.New("invalid mutation type")
	}

	approvals, ok := signed.Mutation.Data.(nodeApprovals)
	if !ok {
		return c, errors.New("invalid node approvals")
	}

	peers, err := c.Peers()
	if err != nil {
		return c, errors.Wrap(err, "get peers")
	}

	if len(peers) != len(approvals.Approvals) {
		return c, errors.New("invalid number of node approvals")
	}

	var parent [32]byte
	for i, approval := range approvals.Approvals {
		if i == 0 {
			parent = approval.Mutation.Parent
		} else if parent != approval.Mutation.Parent {
			return c, errors.New("mismatching node approvals parent")
		}

		pubkey, err := peers[i].PublicKey()
		if err != nil {
			return c, errors.Wrap(err, "get peer public key")
		}

		if !bytes.Equal(pubkey.SerializeCompressed(), approval.Signer) {
			return c, errors.New("invalid node approval signer")
		}

		c, err = approval.Transform(c)
		if err != nil {
			return c, errors.Wrap(err, "transform node approval")
		}
	}

	return c, nil
}
