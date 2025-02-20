// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"sort"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/dkg/frost"
	"github.com/coinbase/kryptology/pkg/sharing"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

var curve = curves.BLS12381G1()

// msgKey identifies the source and target nodes and validator index the message belongs to.
type msgKey struct {
	// ValIdx identifies the distributed validator (Ith parallel participant) the message belongs to.
	// It is 0-indexed.
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
func runFrostParallel(ctx context.Context, tp fTransport, numValidators, numNodes, threshold, shareIdx uint32, dgkCtx string) ([]share, error) {
	validators, err := newFrostParticipants(numValidators, numNodes, threshold, shareIdx, dgkCtx)
	if err != nil {
		return nil, err
	}

	castR1, p2pR1, err := round1(validators)
	if err != nil {
		return nil, err
	}

	log.Debug(ctx, "Sending round 1 messages")

	castR1Result, p2pR1Result, err := tp.Round1(ctx, castR1, p2pR1)
	if err != nil {
		return nil, errors.Wrap(err, "transport round 1")
	}

	log.Debug(ctx, "Received round 1 results")

	castR2, err := round2(validators, castR1Result, p2pR1Result)
	if err != nil {
		return nil, err
	}

	log.Debug(ctx, "Sending round 2 messages")

	castR2Result, err := tp.Round2(ctx, castR2)
	if err != nil {
		return nil, errors.Wrap(err, "transport round 2")
	}

	log.Debug(ctx, "Received round 2 results")

	return makeShares(validators, castR2Result)
}

// newFrostParticipants returns multiple frost dkg participants (one for each parallel validator).
func newFrostParticipants(numValidators, numNodes, threshold, shareIdx uint32, dgkCtx string) (map[uint32]*frost.DkgParticipant, error) {
	var otherIDs []uint32
	for i := uint32(1); i <= numNodes; i++ {
		if i == shareIdx {
			continue
		}
		otherIDs = append(otherIDs, i)
	}

	resp := make(map[uint32]*frost.DkgParticipant)
	for vIdx := range numValidators {
		p, err := frost.NewDkgParticipant(
			shareIdx,
			threshold,
			dgkCtx,
			curve,
			otherIDs...)
		if err != nil {
			return nil, errors.Wrap(err, "new participant")
		}

		resp[vIdx] = p
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
		castR2, err := v.Round2(getRound2Inputs(castR1, p2pR1, vIdx))
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

// getRound2Inputs returns the round 2 inputs of the vIdx'th validator.
func getRound2Inputs(
	castR1 map[msgKey]frost.Round1Bcast,
	p2pR1 map[msgKey]sharing.ShamirShare,
	vIdx uint32,
) (map[uint32]*frost.Round1Bcast, map[uint32]*sharing.ShamirShare) {
	castMap := make(map[uint32]*frost.Round1Bcast)
	for key, cast := range castR1 {
		if key.ValIdx != vIdx {
			continue
		}
		castMap[key.SourceID] = &cast
	}

	shareMap := make(map[uint32]*sharing.ShamirShare)
	for key, share := range p2pR1 {
		if key.ValIdx != vIdx {
			continue
		}
		shareMap[key.SourceID] = &share
	}

	return castMap, shareMap
}

// makeShares returns a slice of shares (one for each validator) from the DKG participants and round 2 results.
func makeShares(
	validators map[uint32]*frost.DkgParticipant,
	r2Result map[msgKey]frost.Round2Bcast,
) ([]share, error) {
	// Get set of public shares for each validator.
	pubShares := make(map[uint32]map[int]tbls.PublicKey) // map[ValIdx]map[SourceID]tbls.PublicKey
	for key, result := range r2Result {
		pubShare, err := pointToPubKey(result.VkShare)
		if err != nil {
			return nil, err
		}

		m, ok := pubShares[key.ValIdx]
		if !ok {
			m = make(map[int]tbls.PublicKey)
			pubShares[key.ValIdx] = m
		}
		m[int(key.SourceID)] = pubShare
	}

	// Sort shares by vIdx
	var vIdxs []int
	for vIdx := range validators {
		vIdxs = append(vIdxs, int(vIdx))
	}
	sort.Ints(vIdxs)

	// Construct DKG result shares.
	var shares []share
	for _, vIdx := range vIdxs {
		v := validators[uint32(vIdx)]

		pubkey, err := pointToPubKey(v.VerificationKey)
		if err != nil {
			return nil, err
		}

		secretShare, err := scalarToSecretShare(v.SkShare)
		if err != nil {
			return nil, err
		}

		shares = append(shares, share{
			PubKey:       pubkey,
			SecretShare:  secretShare,
			PublicShares: pubShares[uint32(vIdx)],
		})
	}

	return shares, nil
}

// pointToPubKey returns the point as a public key.
func pointToPubKey(point curves.Point) (tbls.PublicKey, error) {
	return tblsconv.PubkeyFromBytes(point.ToAffineCompressed())
}

// scalarToSecretShare returns the scalar as a secret key share using the share index.
// Copied from github.com/coinbase/kryptology/test/frost_dkg/bls/main.go.
func scalarToSecretShare(scalar curves.Scalar) (tbls.PrivateKey, error) {
	return tblsconv.PrivkeyFromBytes(scalar.Bytes())
}
