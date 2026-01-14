// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen

import (
	"context"
	"slices"
	"sort"

	kbls "github.com/drand/kyber-bls12381"
	kdkg "github.com/drand/kyber/share/dkg"
	drandbls "github.com/drand/kyber/sign/bdn"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/dkg/share"
	"github.com/obolnetwork/charon/tbls"
)

// High-level protocol overview:
// 1. Each node generates an ephemeral BLS key pair and broadcasts the public key, see board.BroadcastNodePubKey.
// 2. Each node receives all other nodes' public keys before anybody starts the DKG protocol.
// 3. Each node runs the Pedersen DKG protocol, which may run a few exchanges: Deals, Responses, and Justifications.
//    - A single Pedersen DKG run produces a single shared secret key among all nodes.
//    - To run the protocol for multiple validator keys, the protocol is run multiple times (there is room for optimization here).
// 4. Each node broadcasts its share of the validator public key.
// 5. Each node receives all other nodes' shares of the validator public key.
// 6. The resulting []share is collected by the caller via the PushShareFunc callback.

// RunDKG runs the Pedersen DKG protocol using the provided board and configuration.
func RunDKG(ctx context.Context, config *Config, board *Board, numVals int) ([]share.Share, error) {
	// Each node generates an ephemeral key pair (BLS) and broadcasts the public key.
	// This is a prerequisite for the Pedersen DKG protocol.
	nodePrivateKey, nodePubKey := randomKeyPair(config.Suite)

	pkBytes, err := nodePubKey.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "marshal node public key")
	}

	if err := board.BroadcastNodePubKey(ctx, pkBytes); err != nil {
		return nil, errors.Wrap(err, "broadcast node pubkey")
	}

	nodes, _, err := makeNodes(ctx, config, board)
	if err != nil {
		return nil, errors.Wrap(err, "make nodes")
	}

	slices.SortFunc(nodes, func(a, b kdkg.Node) int {
		return int(a.Index) - int(b.Index)
	})

	nonce, err := generateNonce(nodes)
	if err != nil {
		return nil, err
	}

	dkgConfig := &kdkg.Config{
		Longterm:  nodePrivateKey,
		Nonce:     nonce,
		Suite:     config.Suite,
		NewNodes:  nodes,
		Threshold: config.Threshold,
		FastSync:  true,
		Auth:      drandbls.NewSchemeOnG2(kbls.NewBLS12381Suite()),
		Log:       newLogger(log.WithTopic(ctx, "pedersen")),
	}

	log.Info(ctx, "Starting pedersen DKG...")

	shares := make([]share.Share, 0, numVals)

	for range numVals {
		phaser := kdkg.NewTimePhaser(config.PhaseDuration)

		protocol, err := kdkg.NewProtocol(
			dkgConfig,
			board,
			phaser,
			false,
		)
		if err != nil {
			return nil, errors.Wrap(err, "create pedersen DKG protocol")
		}

		go phaser.Start()

		select {
		case <-ctx.Done():
			return nil, errors.New("pedersen DKG context done, protocol aborted")
		case kdkgResult := <-protocol.WaitEnd():
			if kdkgResult.Error != nil {
				return nil, errors.Wrap(kdkgResult.Error, "pedersen DKG protocol failed")
			}

			share, err := processKey(ctx, config, board, kdkgResult.Result.Key)
			if err != nil {
				return nil, errors.Wrap(err, "process pedersen DKG key")
			}

			shares = append(shares, share)
		}
	}

	log.Info(ctx, "Pedersen DKG completed.")

	return shares, nil
}

func makeNodes(ctx context.Context, config *Config, board *Board) ([]kdkg.Node, map[int][][]byte, error) {
	var nodes []kdkg.Node

	nodePubKeys, err := readBoardChannel(ctx, board.IncomingNodePubKeys(), len(config.PeerMap))
	if err != nil {
		return nil, nil, errors.Wrap(err, "read peer pubkeys")
	}

	pubKeyShares := make(map[int][][]byte, 0)

	for i := range nodePubKeys {
		ppk := nodePubKeys[i]
		index := config.PeerMap[ppk.PeerID].PeerIdx

		public, err := unmarshalPoint(config.Suite, ppk.PubKey)
		if err != nil {
			return nil, nil, errors.Wrap(err, "unmarshal node pubkey")
		}

		if len(ppk.PubKeyShares) > 0 {
			shares := make([][]byte, len(ppk.PubKeyShares))
			copy(shares, ppk.PubKeyShares)
			pubKeyShares[index] = shares
		}

		nodes = append(nodes, kdkg.Node{
			Index:  kdkg.Index(index),
			Public: public,
		})
	}

	return nodes, pubKeyShares, nil
}

func processKey(ctx context.Context, config *Config, board *Board, key *kdkg.DistKeyShare) (share.Share, error) {
	secretShare, sharePubKey, err := keyShareToBLS(key)
	if err != nil {
		return share.Share{}, errors.Wrap(err, "convert result to share secret key")
	}

	validatorPubKey, err := distKeyShareToValidatorPubKey(key, config.Suite)
	if err != nil {
		return share.Share{}, errors.Wrap(err, "convert result to validator pub key")
	}

	if err := board.BroadcastValidatorPubKeyShare(ctx, sharePubKey[:]); err != nil {
		return share.Share{}, errors.Wrap(err, "broadcast share pubkey")
	}

	valPubKeyShares, err := readBoardChannel(ctx, board.IncomingValidatorPubKeyShares(), len(config.PeerMap))
	if err != nil {
		return share.Share{}, errors.Wrap(err, "read validator pubkey shares")
	}

	oldShareIndices := make([]int, 0)
	oldShareRevMap := make(map[int][]byte)

	for i := range valPubKeyShares {
		spk := valPubKeyShares[i]
		if len(spk.ValidatorPubKey) == 0 {
			// This is an old node that does not participate in the resharing, skip.
			continue
		}

		shareIndex := config.PeerMap[spk.PeerID].ShareIdx
		oldShareIndices = append(oldShareIndices, shareIndex)
		oldShareRevMap[shareIndex] = spk.ValidatorPubKey
	}

	sort.Ints(oldShareIndices)

	publicShares := make(map[int]tbls.PublicKey)

	for i, oi := range oldShareIndices {
		var pk tbls.PublicKey
		copy(pk[:], oldShareRevMap[oi])
		publicShares[i+1] = pk
	}

	return share.Share{
		PubKey:       validatorPubKey,
		SecretShare:  secretShare,
		PublicShares: publicShares,
	}, nil
}

func readBoardChannel[T any](ctx context.Context, ch <-chan T, count int) ([]T, error) {
	var pubKeys []T

	for range count {
		select {
		case pkd := <-ch:
			pubKeys = append(pubKeys, pkd)
		case <-ctx.Done():
			return nil, errors.New("context done")
		}
	}

	return pubKeys, nil
}
