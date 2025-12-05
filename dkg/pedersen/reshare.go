// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen

import (
	"bytes"
	"context"
	"crypto/sha256"
	"slices"

	"github.com/drand/kyber"
	kbls "github.com/drand/kyber-bls12381"
	kshare "github.com/drand/kyber/share"
	kdkg "github.com/drand/kyber/share/dkg"
	drandbls "github.com/drand/kyber/sign/bdn"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/dkg/share"
	"github.com/obolnetwork/charon/tbls"
)

// RunReshareDKG runs the core reshare protocol for add/remove operators or just reshare.
func RunReshareDKG(ctx context.Context, config *Config, board *Board, shares []share.Share) ([]share.Share, error) {
	if config.Reshare == nil {
		return nil, errors.New("reshare config is nil")
	}

	// Validate that AddedPeers and RemovedPeers are disjoint sets
	for _, addedPeer := range config.Reshare.AddedPeers {
		for _, removedPeer := range config.Reshare.RemovedPeers {
			if addedPeer == removedPeer {
				return nil, errors.New("peer cannot be both added and removed", z.Any("peer_id", addedPeer))
			}
		}
	}

	thisNodeIndex, err := config.ThisNodeIndex()
	if err != nil {
		return nil, err
	}

	// Generating longterm keypair for DKG. The longterm key is used to sign messages only.
	nodePrivateKey, nodePubKey := randomKeyPair(config.Suite)

	pkBytes, err := nodePubKey.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "marshal node public key")
	}

	// We need to exchange the longterm public key and the public key shares (if present)
	sharesPubKeys := make([][]byte, 0)

	for i := range len(shares) {
		sharePubKey, err := tbls.SecretToPublicKey(shares[i].SecretShare)
		if err != nil {
			return nil, errors.Wrap(err, "tbls secret to public key", z.Int("validator_index", i))
		}

		sharesPubKeys = append(sharesPubKeys, sharePubKey[:])
	}

	if err := board.BroadcastNodePubKeyWithShares(ctx, pkBytes, sharesPubKeys); err != nil {
		return nil, errors.Wrap(err, "broadcast node pubkeys with shares")
	}

	nodes, pubKeyShares, err := makeNodes(ctx, config, board)
	if err != nil {
		return nil, errors.Wrap(err, "make nodes")
	}

	slices.SortFunc(nodes, func(a, b kdkg.Node) int {
		return int(a.Index) - int(b.Index)
	})

	// Restore pubkey shares from the exchange
	for i := range len(shares) {
		shares[i].PublicShares = make(map[int]tbls.PublicKey)

		for _, node := range nodes {
			nodeIdx := int(node.Index)
			if len(pubKeyShares[nodeIdx]) > 0 {
				var pk tbls.PublicKey
				copy(pk[:], pubKeyShares[nodeIdx][i])
				shares[i].PublicShares[nodeIdx+1] = pk
			}
		}
	}

	// Restoring DistKeyShares from Charon shares
	distKeyShares := make([]*kdkg.DistKeyShare, 0)

	for i := range len(shares) {
		dks, err := restoreDistKeyShare(shares[i], config.Threshold, thisNodeIndex)
		if err != nil {
			return nil, errors.Wrap(err, "restore distkeyshare", z.Int("validator_index", i))
		}

		distKeyShares = append(distKeyShares, dks)
	}

	// Classify nodes for reshare operation.
	// In KDKG terminology:
	//   - oldNodes: nodes with existing shares (participating in the old cluster)
	//   - newNodes: nodes that will have shares in the new cluster
	//
	// Supported scenarios:
	//   1. Pure reshare (no adds/removes): oldNodes = newNodes = all participating nodes
	//   2. Add-only: oldNodes = existing nodes; newNodes = existing + added nodes
	//   3. Remove-only: oldNodes = all participating nodes; newNodes = participating - removed nodes

	// Determine if this node has existing shares to contribute
	thisIsOldNode := len(distKeyShares) > 0

	oldNodes := make([]kdkg.Node, 0, len(nodes))
	newNodes := make([]kdkg.Node, 0, len(nodes))
	thisIsRemovedNode := false

	for _, node := range nodes {
		isRemoving := false
		isNewlyAdded := false

		// Check if this node is being removed
		for _, removedPeerID := range config.Reshare.RemovedPeers {
			if idx, ok := config.PeerMap[removedPeerID]; ok && idx.PeerIdx == int(node.Index) {
				isRemoving = true
				if idx.PeerIdx == thisNodeIndex {
					thisIsRemovedNode = true
				}

				break
			}
		}

		// Check if this node is newly added
		for _, addedPeerID := range config.Reshare.AddedPeers {
			if idx, ok := config.PeerMap[addedPeerID]; ok && idx.PeerIdx == int(node.Index) {
				isNewlyAdded = true
				break
			}
		}

		// Classify nodes:
		// - oldNodes: nodes that are not newly added (have existing shares)
		// - newNodes: nodes that are not being removed (will be in new cluster)
		if !isNewlyAdded {
			oldNodes = append(oldNodes, node)
		}

		if !isRemoving {
			newNodes = append(newNodes, node)
		}
	}

	// Validate node classification
	if len(config.Reshare.RemovedPeers) > 0 && len(oldNodes) == 0 {
		return nil, errors.New("remove operation requires at least one node with existing shares to participate")
	}

	if len(config.Reshare.AddedPeers) > 0 && len(newNodes) <= len(oldNodes) {
		return nil, errors.New("add operation requires new nodes to join, but all nodes already exist in the cluster")
	}

	// If this node is part of oldNodes (not newly added), it must have shares to contribute
	isNewlyAddedNode := len(config.Reshare.AddedPeers) > 0 && !thisIsOldNode
	if !isNewlyAddedNode && len(distKeyShares) == 0 {
		return nil, errors.New("node is not newly added but has no shares to contribute")
	}

	nonce, err := generateNonce(nodes)
	if err != nil {
		return nil, err
	}

	reshareConfig := &kdkg.Config{
		Longterm:     nodePrivateKey,
		Nonce:        nonce,
		Suite:        config.Suite,
		NewNodes:     newNodes,
		OldNodes:     oldNodes,
		Threshold:    config.Reshare.NewThreshold,
		OldThreshold: config.Threshold,
		FastSync:     true,
		Auth:         drandbls.NewSchemeOnG2(kbls.NewBLS12381Suite()),
		Log:          newLogger(log.WithTopic(ctx, "pedersen")),
	}

	log.Info(ctx, "Starting pedersen reshare...",
		z.Int("oldNodes", len(oldNodes)), z.Int("newNodes", len(newNodes)),
		z.Int("oldThreshold", config.Threshold), z.Int("newThreshold", config.Reshare.NewThreshold),
		z.Bool("thisIsOldNode", thisIsOldNode), z.Bool("thisIsRemovedNode", thisIsRemovedNode))

	newShares := make([]share.Share, 0, config.Reshare.TotalShares)

	for shareNum := range config.Reshare.TotalShares {
		phaser := kdkg.NewTimePhaser(config.PhaseDuration)

		// Nodes with existing shares provide their share to the reshare protocol.
		// New nodes without shares provide public coefficients instead.
		isNodeWithExistingShares := len(distKeyShares) > 0

		if isNodeWithExistingShares {
			// This node has existing shares to contribute to the reshare
			reshareConfig.Share = distKeyShares[shareNum]
			reshareConfig.PublicCoeffs = nil
		} else {
			// This is a new node - restore public coefficients from exchanged public key shares
			commits, err := restoreCommits(pubKeyShares, shareNum, config.Threshold)
			if err != nil {
				return nil, errors.Wrap(err, "restore commits")
			}

			reshareConfig.Share = nil
			reshareConfig.PublicCoeffs = commits
		}

		protocol, err := kdkg.NewProtocol(
			reshareConfig,
			board,
			phaser,
			false,
		)
		if err != nil {
			return nil, errors.Wrap(err, "create pedersen reshare protocol")
		}

		go phaser.Start()

		select {
		case <-ctx.Done():
			return nil, errors.New("pedersen reshare context done, protocol aborted")
		case kdkgResult := <-protocol.WaitEnd():
			if thisIsRemovedNode {
				// This node is being removed and will not receive new shares
				if err := broadcastNoneKey(ctx, config, board); err != nil {
					return nil, err
				}
			} else {
				// This node will be part of the new cluster and receives new shares
				if kdkgResult.Error != nil {
					return nil, errors.Wrap(kdkgResult.Error, "pedersen reshare protocol failed", z.Bool("thisIsOldNode", thisIsOldNode))
				}

				newShare, err := processKey(ctx, config, board, kdkgResult.Result.Key)
				if err != nil {
					return nil, errors.Wrap(err, "process pedersen reshare key")
				}

				newShares = append(newShares, newShare)
			}
		}
	}

	log.Info(ctx, "Pedersen reshare completed.")

	return newShares, nil
}

func broadcastNoneKey(ctx context.Context, config *Config, board *Board) error {
	if err := board.BroadcastValidatorPubKeyShare(ctx, []byte{}); err != nil {
		return errors.Wrap(err, "broadcast none pubkey")
	}

	_, err := readBoardChannel(ctx, board.IncomingValidatorPubKeyShares(), len(config.PeerMap))

	return err
}

// restoreCommitsFromPubShares recovers public polynomial commits from a map of public key shares.
// The nodeIdx in the map is 0-indexed.
func restoreCommitsFromPubShares(pubSharesBytes map[int][]byte, threshold int) ([]kyber.Point, error) {
	var (
		suite          = kbls.NewBLS12381Suite()
		kyberPubShares []*kshare.PubShare
	)

	for nodeIdx, pkBytes := range pubSharesBytes {
		v := suite.G1().Point()
		if err := v.UnmarshalBinary(pkBytes); err != nil {
			return nil, errors.Wrap(err, "unmarshal pubshare")
		}

		kyberPubshare := &kshare.PubShare{
			I: nodeIdx,
			V: v,
		}
		kyberPubShares = append(kyberPubShares, kyberPubshare)
	}

	pubPoly, err := kshare.RecoverPubPoly(suite.G1(), kyberPubShares, threshold, len(pubSharesBytes))
	if err != nil {
		return nil, errors.Wrap(err, "recover pubpoly")
	}

	_, commits := pubPoly.Info()

	return commits, nil
}

func restoreDistKeyShare(keyShare share.Share, threshold int, nodeIdx int) (*kdkg.DistKeyShare, error) {
	// Convert share.Share.PublicShares to the format expected by restoreCommitsFromPubShares
	pubSharesBytes := make(map[int][]byte)
	for shareIdx, pks := range keyShare.PublicShares {
		pubSharesBytes[shareIdx-1] = pks[:]
	}

	commits, err := restoreCommitsFromPubShares(pubSharesBytes, threshold)
	if err != nil {
		return nil, errors.Wrap(err, "restore commits")
	}

	suite := kbls.NewBLS12381Suite()

	v := suite.G1().Scalar()
	if err := v.UnmarshalBinary(keyShare.SecretShare[:]); err != nil {
		return nil, errors.Wrap(err, "unmarshal secret share")
	}

	privShare := &kshare.PriShare{
		I: nodeIdx,
		V: v,
	}

	dks := &kdkg.DistKeyShare{
		Share:   privShare,
		Commits: commits,
	}

	// Sanity check
	validatorPubKey, err := distKeyShareToValidatorPubKey(dks, suite.G1().(kdkg.Suite))
	if err != nil {
		return nil, errors.Wrap(err, "convert distkeyshare to validator pub key")
	}

	if !bytes.Equal(validatorPubKey[:], keyShare.PubKey[:]) {
		return nil, errors.New("restored validator pubkey does not match original validator pubkey")
	}

	return dks, nil
}

func restoreCommits(publicShares map[int][][]byte, shareNum, threshold int) ([]kyber.Point, error) {
	// Extract the specific share's public keys for all nodes
	pubSharesBytes := make(map[int][]byte)
	for nodeIdx, pks := range publicShares {
		pubSharesBytes[nodeIdx] = pks[shareNum]
	}

	return restoreCommitsFromPubShares(pubSharesBytes, threshold)
}

func generateNonce(nodes []kdkg.Node) ([]byte, error) {
	var buf bytes.Buffer

	for _, node := range nodes {
		pkBytes, err := node.Public.MarshalBinary()
		if err != nil {
			return nil, errors.Wrap(err, "marshal node public key")
		}

		_, err = buf.Write(pkBytes)
		if err != nil {
			return nil, errors.Wrap(err, "hash node public key")
		}
	}

	hash := sha256.Sum256(buf.Bytes())

	return hash[:], nil
}
