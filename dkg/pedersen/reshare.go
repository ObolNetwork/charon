// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen

import (
	"bytes"
	"context"
	"crypto/sha256"
	"slices"

	"github.com/drand/kyber"
	kbls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/share"
	kdkg "github.com/drand/kyber/share/dkg"
	drandbls "github.com/drand/kyber/sign/bdn"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/tbls"
)

// RunReshareDKG runs the Pedersen reshare protocol for the existig keys.
func RunReshareDKG(ctx context.Context, config *Config, board *Board, shares []*Share) ([]*Share, error) {
	if config.Reshare == nil {
		return nil, errors.New("reshare config is nil")
	}

	thisNodeIndex, err := config.ThisNodeIndex()
	if err != nil {
		return nil, err
	}

	// Generating longterm keypair for DKG. The longterm key is used to sign messages only.
	nodePrivateKey, nodePubKey := makeKeyPair(config.Suite)

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

		for n := range nodes {
			if len(pubKeyShares[n]) > 0 {
				var pk tbls.PublicKey
				copy(pk[:], pubKeyShares[n][i])
				shares[i].PublicShares[n+1] = pk
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

	oldN := len(nodes) - len(config.Reshare.NewPeers)
	nonce := sha256.Sum256(config.SessionID)
	reshareConfig := &kdkg.Config{
		Longterm:     nodePrivateKey,
		Nonce:        nonce[:],
		Suite:        config.Suite,
		NewNodes:     nodes,
		OldNodes:     nodes[:oldN],
		Threshold:    config.Reshare.NewThreshold,
		OldThreshold: config.Threshold,
		Auth:         drandbls.NewSchemeOnG2(kbls.NewBLS12381Suite()),
		Log:          newLogger(log.WithTopic(ctx, "pedersen")),
	}

	log.Info(ctx, "Starting pedersen reshare...",
		z.Int("oldN", oldN), z.Int("newN", len(nodes)),
		z.Int("oldT", config.Threshold), z.Int("newT", config.Reshare.NewThreshold))

	newShares := make([]*Share, 0, config.Reshare.TotalShares)

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
			if kdkgResult.Error != nil {
				return nil, errors.Wrap(kdkgResult.Error, "pedersen reshare protocol failed")
			}

			newShare, err := processKey(ctx, config, board, kdkgResult.Result.Key)
			if err != nil {
				return nil, errors.Wrap(err, "process pedersen reshare key")
			}

			newShares = append(newShares, newShare)
		}
	}

	log.Info(ctx, "Pedersen reshare completed.")

	return newShares, nil
}

func restoreDistKeyShare(keyShare *Share, threshold int, nodeIdx int) (*kdkg.DistKeyShare, error) {
	var (
		suite          = kbls.NewBLS12381Suite()
		kyberPubShares []*share.PubShare
	)

	for shareIdx, pks := range keyShare.PublicShares {
		v := suite.G1().Point()
		if err := v.UnmarshalBinary(pks[:]); err != nil {
			return nil, errors.Wrap(err, "unmarshal pubshare")
		}

		kyberPubshare := &share.PubShare{
			I: shareIdx - 1,
			V: v,
		}
		kyberPubShares = append(kyberPubShares, kyberPubshare)
	}

	pubPoly, err := share.RecoverPubPoly(suite.G1(), kyberPubShares, threshold, len(keyShare.PublicShares))
	if err != nil {
		return nil, errors.Wrap(err, "recover pubpoly")
	}

	_, commits := pubPoly.Info()

	v := suite.G1().Scalar()
	if err := v.UnmarshalBinary(keyShare.SecretShare[:]); err != nil {
		return nil, errors.Wrap(err, "unmarshal secret share")
	}

	privShare := &share.PriShare{
		I: nodeIdx,
		V: v,
	}

	dks := &kdkg.DistKeyShare{
		Share:   privShare,
		Commits: commits,
	}

	// Sanity check
	validatorPubKey, err := keyShareToValidatorPubKey(dks, suite.G1().(kdkg.Suite))
	if err != nil {
		return nil, errors.Wrap(err, "convert distkeyshare to validator pub key")
	}

	if !bytes.Equal(validatorPubKey[:], keyShare.PubKey[:]) {
		return nil, errors.New("restored validator pubkey does not match original validator pubkey")
	}

	return dks, nil
}

func restoreCommits(publicShares map[int][][]byte, shareNum, threshold int) ([]kyber.Point, error) {
	var (
		suite          = kbls.NewBLS12381Suite()
		kyberPubShares []*share.PubShare
	)

	for nodeIdx, pks := range publicShares {
		v := suite.G1().Point()
		if err := v.UnmarshalBinary(pks[shareNum]); err != nil {
			return nil, errors.Wrap(err, "unmarshal pubshare")
		}

		kyberPubshare := &share.PubShare{
			I: nodeIdx,
			V: v,
		}
		kyberPubShares = append(kyberPubShares, kyberPubshare)
	}

	pubPoly, err := share.RecoverPubPoly(suite.G1(), kyberPubShares, threshold, len(publicShares))
	if err != nil {
		return nil, errors.Wrap(err, "recover pubpoly")
	}

	_, commits := pubPoly.Info()

	return commits, nil
}
