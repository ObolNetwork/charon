// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/drand/kyber"
	kbls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/share"
	kdkg "github.com/drand/kyber/share/dkg"
	drandbls "github.com/drand/kyber/sign/bdn"
	"github.com/drand/kyber/util/random"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
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

const (
	phaseDuration = time.Second
)

// PushShareFunc is a callback function that is called when a new share is created.
type PushShareFunc func(valPubKey tbls.PublicKey, secretShare tbls.PrivateKey, publicShares map[int]tbls.PublicKey)

// RunDKG runs the Pedersen DKG protocol using the provided board and configuration.
func RunDKG(ctx context.Context, config *Config, board *Board, numVals int, push PushShareFunc) error {
	// Each node generates an ephemeral key pair (BLS) and broadcasts the public key.
	// This is a prerequisite for the Pedersen DKG protocol.
	nodePrivateKey, nodePubKey := makeKeyPair(config.Suite)

	pkBytes, err := nodePubKey.MarshalBinary()
	if err != nil {
		return errors.Wrap(err, "marshal node public key")
	}

	if err := board.BroadcastNodePubKey(ctx, pkBytes); err != nil {
		return errors.Wrap(err, "broadcast node pubkey")
	}

	nodes, err := makeNodes(config, board)
	if err != nil {
		return errors.Wrap(err, "make nodes")
	}

	nonce := sha256.Sum256(config.SessionID)
	dkgConfig := &kdkg.Config{
		Longterm:  nodePrivateKey,
		Nonce:     nonce[:],
		Suite:     config.Suite,
		NewNodes:  nodes,
		Threshold: config.Threshold,
		Auth:      drandbls.NewSchemeOnG2(kbls.NewBLS12381Suite()),
	}

	for range numVals {
		// TODO: This phaser implementation is odd, it makes pauses between rounds,
		// relying on all other nodes to complete the round in that time.
		// Unfortunately, kyber does not expose any fine-grained control over the protocol.
		// A better solution would be a signal-based phaser that relies on Board progress.
		phaser := kdkg.NewTimePhaser(phaseDuration)

		protocol, err := kdkg.NewProtocol(
			dkgConfig,
			board,
			phaser,
			false,
		)
		if err != nil {
			return errors.Wrap(err, "create pedersen DKG protocol")
		}

		go phaser.Start()

		select {
		case <-ctx.Done():
			return errors.New("pedersen DKG context done, protocol aborted")
		case kdkgResult := <-protocol.WaitEnd():
			if kdkgResult.Error != nil {
				return errors.Wrap(kdkgResult.Error, "pedersen DKG protocol failed")
			}

			if err = processKey(ctx, config, board, push, kdkgResult.Result.Key); err != nil {
				return errors.Wrap(err, "process pedersen DKG key")
			}
		}
	}

	return nil
}

func makeKeyPair(suite kdkg.Suite) (kyber.Scalar, kyber.Point) {
	private := suite.Scalar().Pick(random.New())
	public := suite.Point().Mul(private, nil)

	return private, public
}

func makeNodes(config *Config, board *Board) ([]kdkg.Node, error) {
	var nodes []kdkg.Node

	for i := 0; i < len(config.PeerMap); i++ {
		pkd := <-board.IncomingNodePubKeys()
		index := config.PeerMap[pkd.PeerID].PeerIdx

		public, err := bytesToPoint(config.Suite, pkd.PubKey)
		if err != nil {
			return nil, errors.Wrap(err, "convert public key to point")
		}

		nodes = append(nodes, kdkg.Node{
			Index:  kdkg.Index(index),
			Public: public,
		})
	}

	return nodes, nil
}

func processKey(ctx context.Context, config *Config, board *Board, push PushShareFunc, key *kdkg.DistKeyShare) error {
	secretShare, sharePubKey, err := resultToShareSecretKey(key)
	if err != nil {
		return errors.Wrap(err, "convert result to share secret key")
	}

	validatorPubKey, err := resultToValidatorPubKey(key, config.Suite)
	if err != nil {
		return errors.Wrap(err, "convert result to validator pub key")
	}

	if err := board.BroadcastValidatorPubKeyShare(ctx, sharePubKey[:]); err != nil {
		return errors.Wrap(err, "broadcast share pubkey")
	}

	publicShares := make(map[int]tbls.PublicKey)

	for i := 0; i < len(config.PeerMap); i++ {
		spk := <-board.IncomingValidatorPubKeyShares()
		shareIndex := config.PeerMap[spk.PeerID].ShareIdx

		var pk tbls.PublicKey
		copy(pk[:], spk.PubKey)
		publicShares[shareIndex] = pk
	}

	push(validatorPubKey, secretShare, publicShares)

	return nil
}

func bytesToPoint(suite kdkg.Suite, b []byte) (kyber.Point, error) {
	point := suite.Point()
	if err := point.UnmarshalBinary(b); err != nil {
		return nil, errors.Wrap(err, "unmarshal point")
	}

	return point, nil
}

func resultToShareSecretKey(result *kdkg.DistKeyShare) (tbls.PrivateKey, tbls.PublicKey, error) {
	privShare := result.PriShare()

	bytsSk, err := privShare.V.MarshalBinary()
	if err != nil {
		return tbls.PrivateKey{}, tbls.PublicKey{}, err
	}

	privKey, err := tblsconv.PrivkeyFromBytes(bytsSk)
	if err != nil {
		return tbls.PrivateKey{}, tbls.PublicKey{}, errors.Wrap(err, "convert privkey from bytes")
	}

	pubKey, err := tbls.SecretToPublicKey(privKey)
	if err != nil {
		return tbls.PrivateKey{}, tbls.PublicKey{}, errors.Wrap(err, "derive pubkey from privkey")
	}

	return privKey, pubKey, nil
}

func resultToValidatorPubKey(result *kdkg.DistKeyShare, suite kdkg.Suite) (tbls.PublicKey, error) {
	exp := share.NewPubPoly(suite, suite.Point().Base(), result.Commitments())

	bytsPK, err := exp.Commit().MarshalBinary()
	if err != nil {
		return tbls.PublicKey{}, errors.Wrap(err, "marshal validator pubkey")
	}

	return tblsconv.PubkeyFromBytes(bytsPK)
}
