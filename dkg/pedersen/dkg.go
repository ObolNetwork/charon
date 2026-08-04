// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen

import (
	"context"
	"slices"
	"time"

	kbls "github.com/drand/kyber-bls12381"
	kdkg "github.com/drand/kyber/share/dkg"
	drandbls "github.com/drand/kyber/sign/bdn"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/share"
	"github.com/obolnetwork/charon/p2p"
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

	threshold := config.Threshold
	if threshold <= 0 {
		threshold = cluster.Threshold(len(nodes))

		log.Info(ctx, "Using default threshold", z.Int("threshold", threshold))
	}

	if err := validateThreshold(len(nodes), threshold); err != nil {
		return nil, err
	}

	log.Info(ctx, "Starting pedersen DKG...")

	shares := make([]share.Share, 0, numVals)

	for i := range numVals {
		nonce, err := generateNonce(nodes, i)
		if err != nil {
			return nil, err
		}

		// Construct a fresh config per protocol run: kyber's NewDistKeyHandler
		// mutates the config it is given, so sharing one across runs is unsafe.
		dkgConfig := &kdkg.Config{
			Longterm:  nodePrivateKey,
			Suite:     config.Suite,
			NewNodes:  nodes,
			Threshold: threshold,
			FastSync:  true,
			Auth:      drandbls.NewSchemeOnG2(kbls.NewBLS12381Suite()),
			Log:       newLogger(log.WithTopic(ctx, "pedersen")),
			Nonce:     nonce,
		}

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

	nodePubKeys, err := readBoardChannel(ctx, board.IncomingNodePubKeys(), config.PeerIDs(),
		func(pk NodePubKeys) peer.ID { return pk.PeerID }, config.collectTimeout())
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

	valPubKeyShares, err := readBoardChannel(ctx, board.IncomingValidatorPubKeyShares(), config.PeerIDs(),
		func(s ValidatorPubKeyShare) peer.ID { return s.PeerID }, config.collectTimeout())
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

	slices.Sort(oldShareIndices)

	publicShares := make(map[int]tbls.PublicKey)

	for _, oi := range oldShareIndices {
		var pk tbls.PublicKey
		copy(pk[:], oldShareRevMap[oi])
		publicShares[oi] = pk
	}

	return share.Share{
		PubKey:       validatorPubKey,
		SecretShare:  secretShare,
		PublicShares: publicShares,
	}, nil
}

// readBoardChannel collects exactly one message per expected peer from the given channel,
// ignoring duplicate deliveries and messages from unexpected peers. It fails with an error
// naming the missing peers if the collection does not complete within the given timeout,
// so a dead peer does not hang the ceremony forever.
func readBoardChannel[T any](ctx context.Context, ch <-chan T, expected []peer.ID, peerIDFn func(T) peer.ID, timeout time.Duration) ([]T, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	expectedSet := make(map[peer.ID]struct{}, len(expected))
	for _, pid := range expected {
		expectedSet[pid] = struct{}{}
	}

	var (
		msgs []T
		seen = make(map[peer.ID]struct{}, len(expected))
	)

	for len(msgs) < len(expected) {
		select {
		case msg := <-ch:
			pid := peerIDFn(msg)
			if _, ok := expectedSet[pid]; !ok {
				continue // Ignore messages from unexpected peers.
			}

			if _, ok := seen[pid]; ok {
				continue // Ignore duplicate deliveries.
			}

			seen[pid] = struct{}{}

			msgs = append(msgs, msg)
		case <-timer.C:
			return nil, errors.New("timed out waiting for DKG messages from peers",
				z.Any("missing_peers", missingPeerNames(expected, seen)),
				z.Int("received", len(msgs)),
				z.Int("expected", len(expected)))
		case <-ctx.Done():
			return nil, errors.New("context done")
		}
	}

	return msgs, nil
}

// missingPeerNames returns the names of the expected peers that no message was received from.
func missingPeerNames(expected []peer.ID, seen map[peer.ID]struct{}) []string {
	var missing []string

	for _, pid := range expected {
		if _, ok := seen[pid]; !ok {
			missing = append(missing, p2p.PeerName(pid))
		}
	}

	return missing
}

// validateThreshold verifies that the threshold is between 1 and nodeCount.
// Note that in case of rotation we cannot increase the threshold beyond the original cluster size.
func validateThreshold(nodeCount, threshold int) error {
	if threshold < 1 {
		return errors.New("threshold is too low", z.Int("threshold", threshold))
	}

	if threshold > nodeCount {
		return errors.New("threshold exceeds node count", z.Int("threshold", threshold), z.Int("nodes", nodeCount))
	}

	return nil
}
