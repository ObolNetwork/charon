// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package dkg

import (
	"context"
	"encoding/json"
	"io"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/tbls"
)

// transport provides secure transport abstraction to keycast.
type transport interface {
	// ServeShares registers a function that serves node share messages until the context is closed.
	ServeShares(context.Context, func(nodeIdx int) (msg []byte, err error))
	// GetShares returns the shares served by a dealer or a permanent error.
	GetShares(ctx context.Context, nodeIdx int) ([]byte, error)
}

// share is the co-validator public key, tbls verifiers, and private key share.
// Each node in the cluster will receive one for each distributed validator.
type share struct {
	PubKey   *bls_sig.PublicKey
	Verifier *sharing.FeldmanVerifier
	Share    *bls_sig.SecretKeyShare
}

// shareMsg is the share message wire format sent by the dealer.
type shareMsg struct {
	PubKey    []byte
	Verifiers [][]byte
	Share     []byte
}

func runKeyCast(ctx context.Context, def cluster.Definition, tx transport, nodeIdx int, random io.Reader) ([]share, error) {
	if nodeIdx == 0 {
		return leadKeyCast(ctx, tx, def, random)
	}

	return joinKeyCast(ctx, tx, nodeIdx)
}

func joinKeyCast(ctx context.Context, tp transport, nodeIdx int) ([]share, error) {
	log.Info(ctx, "Requesting shares from dealer...")

	payload, err := tp.GetShares(ctx, nodeIdx)
	if err != nil {
		return nil, errors.Wrap(err, "get shares")
	}

	var msgs []shareMsg
	if err := json.Unmarshal(payload, &msgs); err != nil {
		return nil, errors.Wrap(err, "unmarshal messages")
	}

	var resp []share
	for _, msg := range msgs {
		share, err := shareFromMsg(msg)
		if err != nil {
			return nil, err
		}

		resp = append(resp, share)
	}

	log.Info(ctx, "Successfully received shares from dealer", z.Int("validators", len(resp)))

	return resp, nil
}

// leadKeyCast creates all shares for the cluster, then serves them via requests until done.
func leadKeyCast(ctx context.Context, tp transport, def cluster.Definition, random io.Reader) ([]share, error) {
	numNodes := len(def.Operators)

	// Create shares for all nodes.
	allShares, err := createShares(def.NumValidators, numNodes, def.Threshold, random)
	if err != nil {
		return nil, err
	}

	if len(allShares) != numNodes {
		return nil, errors.New("bug: sanity check all shares length")
	}

	// Marshal shares as payload for all nodes.
	var (
		payloads = make(map[int][]byte)
		served   = make(map[int]bool)
		resp     []share
	)
	for idx, shares := range allShares {
		if idx == 0 {
			// Store our own shares as the function response.
			resp = shares
			continue
		}

		// Marshal share messages
		var msgs []shareMsg
		for _, s := range shares {
			msg, err := msgFromShare(s)
			if err != nil {
				return nil, err
			}
			msgs = append(msgs, msg)
		}

		payload, err := json.Marshal(msgs)
		if err != nil {
			return nil, errors.Wrap(err, "marshal msgs")
		}
		payloads[idx] = payload
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	log.Info(ctx, "Node selected as dealer, serving shares...")

	tp.ServeShares(ctx, func(nodeIdx int) ([]byte, error) {
		payload, ok := payloads[nodeIdx]
		if !ok {
			return nil, errors.New("unknown node index", z.Int("nodeIdx", nodeIdx))
		}

		log.Info(ctx, "Serving shares to node", z.Int("nodeIdx", nodeIdx))

		served[nodeIdx] = true

		if len(served) >= numNodes-1 {
			log.Info(ctx, "Successfully shared to all other nodes", z.Int("num_nodes", len(served)))
			cancel() // We have served all the nodes
		}

		return payload, nil
	})

	return resp, nil
}

// createShares returns a slice of shares to send to each node.
func createShares(numValidators, numNodes, threshold int, random io.Reader) ([][]share, error) {
	resp := make([][]share, numNodes)
	for i := 0; i < numValidators; i++ {
		pubkey, secret, err := tbls.Keygen()
		if err != nil {
			return nil, err
		}

		shares, verifier, err := tbls.SplitSecret(secret, threshold, numNodes, random)
		if err != nil {
			return nil, err
		}

		if len(shares) != numNodes {
			return nil, errors.New("bug: sanity check length of shares")
		}

		for ni := 0; ni < numNodes; ni++ {
			resp[ni] = append(resp[ni], share{
				PubKey:   pubkey,
				Verifier: verifier,
				Share:    shares[ni],
			})
		}
	}

	return resp, nil
}

// msgFromShare returns a new share message to send over the wire.
func msgFromShare(s share) (shareMsg, error) {
	pk, err := s.PubKey.MarshalBinary()
	if err != nil {
		return shareMsg{}, errors.Wrap(err, "marshal pubkey")
	}

	var verifiers [][]byte
	for _, commitment := range s.Verifier.Commitments {
		verifiers = append(verifiers, commitment.ToAffineCompressed())
	}

	b, err := s.Share.MarshalBinary()
	if err != nil {
		return shareMsg{}, errors.Wrap(err, "marshal share")
	}

	return shareMsg{
		PubKey:    pk,
		Verifiers: verifiers,
		Share:     b,
	}, nil
}

// shareFromMsg returns the share by unmarshalling the wire message types.
func shareFromMsg(msg shareMsg) (share, error) {
	pubKey := new(bls_sig.PublicKey)
	if err := pubKey.UnmarshalBinary(msg.PubKey); err != nil {
		return share{}, errors.Wrap(err, "unmarshal pubkey")
	}

	var commitments []curves.Point
	for _, v := range msg.Verifiers {
		c, err := curves.BLS12381G1().Point.FromAffineCompressed(v)
		if err != nil {
			return share{}, errors.Wrap(err, "verifier hex")
		}

		commitments = append(commitments, c)
	}

	secretShare := new(bls_sig.SecretKeyShare)
	if err := secretShare.UnmarshalBinary(msg.Share); err != nil {
		return share{}, errors.Wrap(err, "unmarshal pubkey")
	}

	return share{
		PubKey:   pubKey,
		Verifier: &sharing.FeldmanVerifier{Commitments: commitments},
		Share:    secretShare,
	}, nil
}
