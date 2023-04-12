// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"encoding/json"
	"sort"
	"sync"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
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
	PubKey      tbls.PublicKey
	SecretShare tbls.PrivateKey

	PublicShares map[int]tbls.PublicKey // map[shareIdx]tbls.PublicKey
}

// shareMsg is the share message wire format sent by the dealer.
type shareMsg struct {
	PubKey      []byte
	PubShares   [][]byte
	SecretShare []byte
}

func runKeyCast(ctx context.Context, def cluster.Definition, tx kcTransport, nodeIdx int) ([]share, error) {
	if nodeIdx == 0 {
		return leadKeyCast(ctx, tx, def)
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
func leadKeyCast(ctx context.Context, tp kcTransport, def cluster.Definition) ([]share, error) {
	numNodes := len(def.Operators)

	// Create shares for all nodes.
	allShares, err := createShares(def.NumValidators, numNodes, def.Threshold)
	if err != nil {
		return nil, err
	}

	if len(allShares) != numNodes {
		return nil, errors.New("bug: sanity check all shares length")
	}

	// Marshal shares as payload for all nodes.
	var (
		serveMutex sync.Mutex

		// Shared server state.
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
			msg := msgFromShare(s)
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
		serveMutex.Lock()
		defer serveMutex.Unlock()

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
func createShares(numValidators, numNodes, threshold int) ([][]share, error) {
	resp := make([][]share, numNodes)
	for i := 0; i < numValidators; i++ {
		rootSecret, err := tbls.GenerateSecretKey()
		if err != nil {
			return nil, err
		}

		rootPubkey, err := tbls.SecretToPublicKey(rootSecret)
		if err != nil {
			return nil, err
		}

		shares, err := tbls.ThresholdSplit(rootSecret, uint(numNodes), uint(threshold))
		if err != nil {
			return nil, err
		}

		if len(shares) != numNodes {
			return nil, errors.New("bug: sanity check length of shares")
		}

		pubShares := make(map[int]tbls.PublicKey)
		for idx, privShare := range shares {
			privShare := privShare
			idx := idx
			pubShare, err := tbls.SecretToPublicKey(privShare)
			if err != nil {
				return nil, errors.Wrap(err, "can't obtain pubkey from secret", z.Int("index", idx))
			}

			pubShares[idx] = pubShare
		}

		for nodeIdx := 0; nodeIdx < numNodes; nodeIdx++ {
			resp[nodeIdx] = append(resp[nodeIdx], share{
				PubKey:       rootPubkey,
				PublicShares: pubShares,
				SecretShare:  shares[nodeIdx+1],
			})
		}
	}

	return resp, nil
}

// msgFromShare returns a new share message to send over the wire.
func msgFromShare(s share) shareMsg {
	pubkey := s.PubKey[:]

	// Sort pub shares by id/index.
	var pubSharesIDs []int
	for id := range s.PublicShares {
		pubSharesIDs = append(pubSharesIDs, id)
	}
	sort.Ints(pubSharesIDs)

	var pubShares [][]byte
	for _, id := range pubSharesIDs {
		key := s.PublicShares[id]
		pubShares = append(pubShares, key[:])
	}

	secretShare := s.SecretShare[:]

	return shareMsg{
		PubKey:      pubkey,
		SecretShare: secretShare,
		PubShares:   pubShares,
	}
}

// shareFromMsg returns the share by unmarshalling the wire message types.
func shareFromMsg(msg shareMsg) (share, error) {
	pubKey, err := tblsconv.PubkeyFromBytes(msg.PubKey)
	if err != nil {
		return share{}, errors.Wrap(err, "public key from bytes")
	}
	pubShares := make(map[int]tbls.PublicKey)

	for id, bytes := range msg.PubShares {
		pubKey, err := tblsconv.PubkeyFromBytes(bytes)
		if err != nil {
			return share{}, errors.Wrap(err, "public key from bytes")
		}
		pubShares[id+1] = pubKey // Public shares IDs are 1-indexed.
	}

	secretShare, err := tblsconv.PrivkeyFromBytes(msg.SecretShare)
	if err != nil {
		return share{}, errors.Wrap(err, "private key from bytes")
	}

	return share{
		PubKey:       pubKey,
		SecretShare:  secretShare,
		PublicShares: pubShares,
	}, nil
}
