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

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/dkg/frost"
	"github.com/coinbase/kryptology/pkg/sharing"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
)

// msgKey identifies the source and target nodes and validator index the message belongs to.
type msgKey struct {
	// ValIdx identifies the distributed validator (Ith parallel participant) the message belongs to.
	ValIdx uint32

	// SourceID identifies the source node/participant ID of the message.
	// It is 1-indexed and equivalent to `cluster.NodeIdx.ShareIdx`.
	SourceID uint32

	// TargetID identifies the target node/participant ID of the message.
	// It is 1-indexed and equivalent to `cluster.NodeIdx.ShareIdx`.
	// The zero value indicates outgoing broadcast messages.
	TargetID uint32
}

// fTransport abstracts the transport of frost DKG messages.
type fTransport interface {
	// Round1 returns results of all round 1 communication; the received round 1 broadcasts from all other nodes
	// and the round 1 P2P sends to this node.
	Round1(context.Context, map[msgKey]frost.Round1Bcast, map[msgKey]sharing.ShamirShare) (
		map[msgKey]frost.Round1Bcast, map[msgKey]sharing.ShamirShare, error)

	// Round2 returns results of all round 2 communication; the received round 2 broadcasts from all other nodes.
	Round2(context.Context, map[msgKey]frost.Round2Bcast) (map[msgKey]frost.Round2Bcast, error)
}

// runFrostParallel runs numValidators Frost DKG processes in parallel (sharing transport rounds)
// and returns a list of shares (one for each distributed validator).
//nolint:deadcode // Will be tested and integrated in subsequent PRs.
func runFrostParallel(ctx context.Context, tp fTransport, numValidators, numNodes, threshold, shareIdx uint32, dgkCtx string) ([]share, error) {
	validators, err := newFrostParticipants(numValidators, numNodes, threshold, shareIdx, dgkCtx)
	if err != nil {
		return nil, err
	}

	castR1, p2pR1, err := round1(validators)
	if err != nil {
		return nil, err
	}

	castR1Result, p2pR1Result, err := tp.Round1(ctx, castR1, p2pR1)
	if err != nil {
		return nil, errors.Wrap(err, "transport round 1")
	}

	castR2, err := round2(validators, castR1Result, p2pR1Result)
	if err != nil {
		return nil, err
	}

	castR2Result, err := tp.Round2(ctx, castR2)
	if err != nil {
		return nil, errors.Wrap(err, "transport round 2")
	}

	return makeShares(validators, castR2Result)
}

// newFrostParticipant returns multiple frost dkg participants (one for each parallel validator).
func newFrostParticipants(numValidators, numNodes, threshold, shareIdx uint32, dgkCtx string) (map[uint32]*frost.DkgParticipant, error) {
	var otherIDs []uint32
	for i := uint32(1); i <= numNodes; i++ {
		if i == shareIdx {
			continue
		}
		otherIDs = append(otherIDs, i)
	}

	resp := make(map[uint32]*frost.DkgParticipant)
	for i := uint32(0); i < numValidators; i++ {
		p, err := frost.NewDkgParticipant(
			shareIdx,
			threshold,
			dgkCtx,
			curves.BLS12381G1(),
			otherIDs...)
		if err != nil {
			return nil, errors.Wrap(err, "new participant")
		}

		resp[i] = p
	}

	return resp, nil
}

// round1 executes round 1 for each validator and returns all round 1
// broadcast and p2p messages for all validators.
func round1(validators map[uint32]*frost.DkgParticipant) (map[msgKey]frost.Round1Bcast, map[msgKey]sharing.ShamirShare, error) {
	var (
		castResults = make(map[msgKey]frost.Round1Bcast)
		p2pResults  = make(map[msgKey]sharing.ShamirShare)
	)
	for vIdx, v := range validators {
		cast, p2p, err := v.Round1(nil)
		if err != nil {
			return nil, nil, errors.Wrap(err, "exec round 1")
		}

		castResults[msgKey{
			ValIdx:   vIdx,
			SourceID: v.Id,
			TargetID: 0, // Broadcast
		}] = *cast

		for targetID, shamirShare := range p2p {
			p2pResults[msgKey{
				ValIdx:   vIdx,
				SourceID: v.Id,
				TargetID: targetID,
			}] = *shamirShare
		}
	}

	return castResults, p2pResults, nil
}

// round2 executes round 2 for each validator and returns all round 2
// broadcast messages for all validators.
func round2(
	validators map[uint32]*frost.DkgParticipant,
	castR1 map[msgKey]frost.Round1Bcast,
	p2pR1 map[msgKey]sharing.ShamirShare,
) (map[msgKey]frost.Round2Bcast, error) {
	castResults := make(map[msgKey]frost.Round2Bcast)
	for vIdx, v := range validators {
		// Extract vIdx'th validator round 2 inputs.
		var (
			castMap  = make(map[uint32]*frost.Round1Bcast)
			shareMap = make(map[uint32]*sharing.ShamirShare)
		)
		for key, cast := range castR1 {
			if key.ValIdx != vIdx {
				continue
			}
			if key.TargetID != v.Id {
				continue
			}
			cast := cast // Copy loop variable
			castMap[key.SourceID] = &cast
		}
		for key, share := range p2pR1 {
			if key.ValIdx != vIdx {
				continue
			}
			if key.TargetID != v.Id {
				continue
			}
			share := share // Copy loop variable
			shareMap[key.SourceID] = &share
		}

		castR2, err := v.Round2(castMap, shareMap)
		if err != nil {
			return nil, errors.Wrap(err, "exec round 2")
		}

		castResults[msgKey{
			ValIdx:   vIdx,
			SourceID: v.Id,
			TargetID: 0, // Broadcast
		}] = *castR2
	}

	return castResults, nil
}

// makeShares returns a slice of shares (one for each validator) from the DKG participants and round 2 results.
func makeShares(validators map[uint32]*frost.DkgParticipant, r2Result map[msgKey]frost.Round2Bcast) ([]share, error) {
	// Get our ID from any validator (they all have our ID). 
	targetID := validators[0].Id

	// Get set of public shares for each validator.
	pubShares := make(map[uint32]map[uint32]*bls_sig.PublicKey) // map[ValIdx]map[SourceID]*bls_sig.PublicKey
	for key, result := range r2Result {
		if key.TargetID != targetID {
			continue
		}
		pubShare, err := pointToPubKey(result.VkShare)
		if err != nil {
			return nil, err
		}

		m, ok := pubShares[key.ValIdx]
		if !ok {
			m = make(map[uint32]*bls_sig.PublicKey)
			pubShares[key.ValIdx] = m
		}
		m[key.SourceID] = pubShare
	}

	var shares []share
	for vIdx, v := range validators {
		pubkey, err := pointToPubKey(v.VerificationKey)
		if err != nil {
			return nil, err
		}

		secretShare, err := scalarToSecretShare(v.Id, v.SkShare)
		if err != nil {
			return nil, err
		}

		vIdx := vIdx // Copy loop variable
		share := share{
			PubKey:       pubkey,
			Share:        secretShare,
			PublicShares: pubShares[vIdx],
		}

		shares = append(shares, share)
	}

	return shares, nil
}

func pointToPubKey(point curves.Point) (*bls_sig.PublicKey, error) {
	pk := new(bls_sig.PublicKey)
	err := pk.UnmarshalBinary(point.ToAffineCompressed())
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal pubkey pooint")
	}

	return pk, nil
}

// scalarToSecretShare returns the scalar as a secret key share using the share index.
// Copied from github.com/coinbase/kryptology/test/frost_dkg/bls/main.go.
func scalarToSecretShare(shareIdx uint32, scalar curves.Scalar) (*bls_sig.SecretKeyShare, error) {
	share := sharing.ShamirShare{
		Id:    shareIdx,
		Value: scalar.Bytes(),
	}
	sk := share.Bytes()

	// secret share expects 1 byte identifier at the end of the array
	skBytes := make([]byte, bls_sig.SecretKeyShareSize)
	copy(skBytes, sk[4:])
	skBytes[bls_sig.SecretKeyShareSize-1] = sk[3]

	skShare := new(bls_sig.SecretKeyShare)
	err := skShare.UnmarshalBinary(skBytes)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal secret share")
	}

	return skShare, nil
}
