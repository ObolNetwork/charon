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
	"sort"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/tbls"
)

// kcTransport provides secure transport abstraction to keycast.
type kcTransport interface {
	// ServeShares registers a function that serves node share messages until the context is closed.
	ServeShares(context.Context, func(nodeIdx int) (msg []byte, err error))
	// GetShares returns the shares served by a dealer or a permanent error.
	GetShares(ctx context.Context, nodeIdx int) ([]byte, error)
}

// share is the co-validator public key, tbls public shares, and private key share.
// Each node in the cluster will receive one for each distributed validator.
type share struct {
	PubKey      *bls_sig.PublicKey
	SecretShare *bls_sig.SecretKeyShare

	PublicShares map[int]*bls_sig.PublicKey // map[shareIdx]*bls_sig.PublicKey
}

// shareMsg is the share message wire format sent by the dealer.
type shareMsg struct {
	PubKey      []byte
	PubShares   [][]byte
	SecretShare []byte
}

func runKeyCast(ctx context.Context, def cluster.Definition, tx kcTransport, nodeIdx int, random io.Reader) ([]share, error) {
	if nodeIdx == 0 {
		return leadKeyCast(ctx, tx, def, random)
	}

	return joinKeyCast(ctx, tx, nodeIdx)
}

func joinKeyCast(ctx context.Context, tp kcTransport, nodeIdx int) ([]share, error) {
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
func leadKeyCast(ctx context.Context, tp kcTransport, def cluster.Definition, random io.Reader) ([]share, error) {
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
		tss, shares, err := tbls.GenerateTSS(threshold, numNodes, random)
		if err != nil {
			return nil, err
		}

		if len(shares) != numNodes {
			return nil, errors.New("bug: sanity check length of shares")
		}

		for nodeIdx := 0; nodeIdx < numNodes; nodeIdx++ {
			resp[nodeIdx] = append(resp[nodeIdx], share{
				PubKey:       tss.PublicKey(),
				PublicShares: tss.PublicShares(),
				SecretShare:  shares[nodeIdx],
			})
		}
	}

	return resp, nil
}

// msgFromShare returns a new share message to send over the wire.
func msgFromShare(s share) (shareMsg, error) {
	pubkey, err := s.PubKey.MarshalBinary()
	if err != nil {
		return shareMsg{}, errors.Wrap(err, "marshal pubkey")
	}

	// Sort pub shares by id/index.
	var pubSharesIDs []int
	for id := range s.PublicShares {
		pubSharesIDs = append(pubSharesIDs, int(id))
	}
	sort.Ints(pubSharesIDs)

	var pubShares [][]byte
	for _, id := range pubSharesIDs {
		b, err := s.PublicShares[id].MarshalBinary()
		if err != nil {
			return shareMsg{}, errors.Wrap(err, "marshal public share")
		}
		pubShares = append(pubShares, b)
	}

	secretShare, err := s.SecretShare.MarshalBinary()
	if err != nil {
		return shareMsg{}, errors.Wrap(err, "marshal secretShare share")
	}

	return shareMsg{
		PubKey:      pubkey,
		SecretShare: secretShare,
		PubShares:   pubShares,
	}, nil
}

// shareFromMsg returns the share by unmarshalling the wire message types.
func shareFromMsg(msg shareMsg) (share, error) {
	pubKey := new(bls_sig.PublicKey)
	if err := pubKey.UnmarshalBinary(msg.PubKey); err != nil {
		return share{}, errors.Wrap(err, "unmarshal pubkey")
	}

	pubShares := make(map[int]*bls_sig.PublicKey)
	for id, bytes := range msg.PubShares {
		pubShare := new(bls_sig.PublicKey)
		if err := pubShare.UnmarshalBinary(bytes); err != nil {
			return share{}, errors.Wrap(err, "unmarshal public share")
		}

		pubShares[id+1] = pubShare // Public shares IDs are 1-indexed.
	}

	secretShare := new(bls_sig.SecretKeyShare)
	if err := secretShare.UnmarshalBinary(msg.SecretShare); err != nil {
		return share{}, errors.Wrap(err, "unmarshal pubkey")
	}

	return share{
		PubKey:       pubKey,
		SecretShare:  secretShare,
		PublicShares: pubShares,
	}, nil
}
