// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"sort"

	"github.com/obolnetwork/charon/tbls"
)

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
