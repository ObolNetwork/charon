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

	// Determine which nodes are old vs new
	// For remove-only scenarios (no new nodes added):
	//   - oldNodes: all participating nodes (even if removed, but participating)
	//   - newNodes: participating nodes excluding those being removed
	// For add-only scenarios (no nodes removed):
	//   - oldNodes: participating old nodes only (excludes new nodes)
	//   - newNodes: all participating nodes (old + new)

	thisIsOldNode := false

	for _, oid := range config.Reshare.OldPeers {
		idx, ok := config.PeerMap[oid]
		if !ok {
			// Removed node is not in peer map (not participating)
			continue
		}

		if idx.PeerIdx == thisNodeIndex {
			thisIsOldNode = true
			break
		}
	}

	// The nodes slice contains all participating nodes (sorted by index)
	// For remove scenarios, removed nodes don't participate and aren't in this list
	// Split the participating nodes into old and new based on config
	numNewPeers := len(config.Reshare.NewPeers)
	numOldNodes := len(nodes) - numNewPeers

	// oldNodes are the first N-numNewPeers nodes (assuming new nodes come last after old nodes)
	oldNodes := make([]kdkg.Node, numOldNodes)
	copy(oldNodes, nodes[:numOldNodes])

	// newNodes starts with all participating nodes
	newNodes := make([]kdkg.Node, 0, len(nodes))
	for _, node := range nodes {
		// Check if this node is being removed
		isRemoving := false

		for _, oid := range config.Reshare.OldPeers {
			if idx, ok := config.PeerMap[oid]; ok && idx.PeerIdx == int(node.Index) {
				isRemoving = true
				break
			}
		}

		// Only include nodes that are NOT being removed
		if !isRemoving {
			newNodes = append(newNodes, node)
		}
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
		z.Bool("removed", thisIsOldNode))

	newShares := make([]share.Share, 0, config.Reshare.TotalShares)

	for shareNum := range config.Reshare.TotalShares {
		phaser := kdkg.NewTimePhaser(config.PhaseDuration)

		if len(distKeyShares) > 0 {
			// Share is to be set by old nodes only
			reshareConfig.Share = distKeyShares[shareNum]
			reshareConfig.PublicCoeffs = nil
		} else {
			// PublicCoeffs is to be set by new nodes only, but not the Share
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
			if thisIsOldNode {
				if err := broadcastNoneKey(ctx, config, board); err != nil {
					return nil, err
				}
			} else {
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
