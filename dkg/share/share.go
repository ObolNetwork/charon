// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package share

import (
	"sort"

	"github.com/obolnetwork/charon/tbls"
)

// Share is the co-validator public key, tbls public shares, and private key share.
// Each node in the cluster will receive one for each distributed validator.
type Share struct {
	PubKey      tbls.PublicKey
	SecretShare tbls.PrivateKey

	PublicShares map[int]tbls.PublicKey // map[shareIdx]tbls.PublicKey
}

// Msg is the share message wire format sent by the dealer.
type Msg struct {
	PubKey      []byte
	PubShares   [][]byte
	SecretShare []byte
}

// MsgFromShare returns a new share message to send over the wire.
func MsgFromShare(s Share) Msg {
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

	return Msg{
		PubKey:      pubkey,
		SecretShare: secretShare,
		PubShares:   pubShares,
	}
}
