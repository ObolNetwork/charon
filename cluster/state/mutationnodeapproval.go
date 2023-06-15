// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	"bytes"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	statepb "github.com/obolnetwork/charon/cluster/statepb/v1"
)

// SignNodeApproval signs a node approval mutation.
func SignNodeApproval(parent []byte, secret *k1.PrivateKey) (*statepb.SignedMutation, error) {
	emptyAny, err := anypb.New(&statepb.Empty{})
	if err != nil {
		return nil, errors.Wrap(err, "empty to any")
	}

	if len(parent) != hashLen {
		return nil, errors.New("invalid parent hash")
	}

	return SignK1(&statepb.Mutation{
		Parent:    parent,
		Type:      string(TypeNodeApproval),
		Timestamp: nowFunc(),
		Data:      emptyAny,
	}, secret)
}

// NewNodeApprovalsComposite returns a new composite node approvals mutation.
// Note the approvals must be for all nodes in the cluster ordered by peer index.
func NewNodeApprovalsComposite(approvals []*statepb.SignedMutation) (*statepb.SignedMutation, error) {
	if len(approvals) == 0 {
		return nil, errors.New("empty node approvals")
	}

	var parent []byte
	for i, approval := range approvals {
		if i == 0 {
			parent = approval.Mutation.Parent
		} else if !bytes.Equal(parent, approval.Mutation.Parent) {
			return nil, errors.New("mismatching node approvals parent")
		}

		if err := verifyNodeApproval(approval); err != nil {
			return nil, errors.Wrap(err, "verify node approval", z.Int("index", i))
		}
	}

	anyList, err := anypb.New(&statepb.SignedMutationList{
		Mutations: approvals,
	})
	if err != nil {
		return nil, errors.Wrap(err, "mutations to any")
	}

	return &statepb.SignedMutation{
		Mutation: &statepb.Mutation{
			Parent:    parent,
			Type:      string(TypeNodeApprovals),
			Timestamp: nowFunc(),
			Data:      anyList,
		},
		// Composite types do not have signatures
	}, nil
}

// verifyNodeApproval returns an error if the input signed mutation is not valid.
func verifyNodeApproval(signed *statepb.SignedMutation) error {
	if MutationType(signed.Mutation.Type) != TypeNodeApproval {
		return errors.New("invalid mutation type")
	}

	empty := new(statepb.Empty)
	if err := signed.Mutation.Data.UnmarshalTo(empty); err != nil {
		return errors.Wrap(err, "invalid node approval data")
	}

	return verifyK1SignedMutation(signed)
}

// transformNodeApprovals transforms the cluster state with the node approvals.
func transformNodeApprovals(c *statepb.Cluster, signed *statepb.SignedMutation) (*statepb.Cluster, error) {
	if MutationType(signed.Mutation.Type) != TypeNodeApprovals {
		return c, errors.New("invalid mutation type")
	}

	list := new(statepb.SignedMutationList)
	if err := signed.Mutation.Data.UnmarshalTo(list); err != nil {
		return c, errors.New("invalid node approval data")
	}

	peers, err := ClusterPeers(c)
	if err != nil {
		return c, errors.Wrap(err, "get peers")
	}

	if len(peers) != len(list.Mutations) {
		return c, errors.New("invalid number of node approvals")
	}

	var parent []byte
	for i, approval := range list.Mutations {
		if i == 0 {
			parent = approval.Mutation.Parent
		} else if !bytes.Equal(parent, approval.Mutation.Parent) {
			return c, errors.New("mismatching node approvals parent")
		}

		pubkey, err := peers[i].PublicKey()
		if err != nil {
			return c, errors.Wrap(err, "get peer public key")
		}

		if !bytes.Equal(pubkey.SerializeCompressed(), approval.Signer) {
			return c, errors.New("invalid node approval signer")
		}

		c, err = Transform(c, approval)
		if err != nil {
			return c, errors.Wrap(err, "transform node approval")
		}
	}

	return c, nil
}
