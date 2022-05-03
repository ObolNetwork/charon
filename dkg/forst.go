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
	"encoding/binary"
	"io"
	"strconv"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/dkg/frost"
	"github.com/coinbase/kryptology/pkg/sharing"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
)

// fTransport abstracts the transport of frost DKG messages.
type fTransport interface {
	// Round1 returns results of all round 1 communication; the received round 1 broadcasts from all other nodes
	// and the round 1 P2P sends to this node.
	Round1(
		context.Context,
		[]frost.Round1Bcast,
		[]frost.Round1P2PSend,
	) (
		map[uint32][]frost.Round1Bcast,
		map[uint32][]sharing.ShamirShare,
		error,
	)

	// Round2 returns results of all round 2 communication; the received round 2 broadcasts from all other nodes.
	Round2(context.Context, []frost.Round2Bcast) (map[uint32][]frost.Round2Bcast, error)
}

// runFrostParallel runs def.NumValidator Frost DKG processes in parallel (sharing transport rounds)
// and returns a list of shares (one for each distributed validator).
//nolint:deadcode // Will be tested and integrated in subsequent PRs.
func runFrostParallel(ctx context.Context, def cluster.Definition, tp fTransport, shareIdx int, random io.Reader) ([]share, error) {
	validators, err := newFrostParticipants(def, shareIdx, random)
	if err != nil {
		return nil, err
	}

	castR1, p2pR1, err := round1(validators)
	if err != nil {
		return nil, err
	}

	if len(castR1) != def.NumValidators ||
		len(p2pR1) != def.NumValidators {
		return nil, errors.New("bug: round 1 message count incorrect")
	}

	castR1Result, p2pR1Result, err := tp.Round1(ctx, castR1, p2pR1)
	if err != nil {
		return nil, errors.Wrap(err, "transport round 1")
	}

	if len(castR1Result) != len(def.Operators) ||
		len(p2pR1Result) != len(def.Operators) {
		return nil, errors.New("bug: round 1 result count incorrect")
	}

	castR2, err := round2(validators, castR1Result, p2pR1Result)
	if err != nil {
		return nil, errors.Wrap(err, "exec round 2")
	}

	if len(castR2) != def.NumValidators {
		return nil, errors.New("bug: round 2 message count incorrect")
	}

	castR2Result, err := tp.Round2(ctx, castR2)
	if err != nil {
		return nil, errors.Wrap(err, "transport round 1")
	}

	if len(castR2Result) != len(def.Operators) {
		return nil, errors.New("bug: round 2 result count incorrect")
	}

	return makeShares(validators, castR2Result)
}

// round1 executes round 1 for each validator and returns all round 1
// broadcast and p2p messages for all validators.
func round1(validators []*frost.DkgParticipant) ([]frost.Round1Bcast, []frost.Round1P2PSend, error) {
	var (
		castResults []frost.Round1Bcast
		p2pResults  []frost.Round1P2PSend
	)
	for _, v := range validators {
		cast, p2p, err := v.Round1(nil)
		if err != nil {
			return nil, nil, errors.Wrap(err, "exec round 1")
		}

		castResults = append(castResults, *cast)
		p2pResults = append(p2pResults, p2p)
	}

	return castResults, p2pResults, nil
}

// round2 executes round 2 for each validator and returns all round 2
// broadcast messages for all validators.
func round2(
	validators []*frost.DkgParticipant,
	castR1 map[uint32][]frost.Round1Bcast,
	p2pR1 map[uint32][]sharing.ShamirShare,
) ([]frost.Round2Bcast, error) {
	var castResults []frost.Round2Bcast
	for i, v := range validators {
		// Extract Ith validator round 2 inputs.
		var (
			cast = make(map[uint32]*frost.Round1Bcast)
			p2p  = make(map[uint32]*sharing.ShamirShare)
		)
		for id, casts := range castR1 {
			if len(casts) >= i {
				return nil, errors.New("too few round 1 broadcast inputs")
			}
			cast[id] = &casts[i]
		}
		for id, p2ps := range p2pR1 {
			if len(p2ps) >= i {
				return nil, errors.New("too few round 1 p2p inputs")
			}
			p2p[id] = &p2ps[i]
		}

		castR2, err := v.Round2(cast, p2p)
		if err != nil {
			return nil, errors.Wrap(err, "exec round 1")
		}

		castResults = append(castResults, *castR2)
	}

	return castResults, nil
}

// makeShares returns a slice of shares (one for each validator) from the DKG participants and round 2 results.
func makeShares(validators []*frost.DkgParticipant, r2Result map[uint32][]frost.Round2Bcast) ([]share, error) {
	// Get set of public shares for each validator.
	pubShares := make([][]*bls_sig.PublicKey, len(validators))
	for _, results := range r2Result {
		for i, result := range results {
			pubShare, err := pointToPubKey(result.VkShare)
			if err != nil {
				return nil, err
			}
			pubShares[i] = append(pubShares[i], pubShare)
		}
	}

	var shares []share
	for i, v := range validators {
		pubkey, err := pointToPubKey(v.VerificationKey)
		if err != nil {
			return nil, err
		}

		secretShare, err := scalarToSecretShare(v.Id, v.SkShare)
		if err != nil {
			return nil, err
		}

		share := share{
			PubKey:       pubkey,
			Share:        secretShare,
			PublicShares: pubShares[i],
		}

		shares = append(shares, share)
	}

	return shares, nil
}

// newFrostParticipant returns multiple frost dkg participants (one for each parallel validator).
func newFrostParticipants(def cluster.Definition, shareIdx int, random io.Reader) ([]*frost.DkgParticipant, error) {
	var otherIDs []uint32
	for i := 1; i <= len(def.Operators); i++ {
		if i == shareIdx {
			continue
		}
		otherIDs = append(otherIDs, uint32(i))
	}

	var resp []*frost.DkgParticipant
	for i := 0; i < def.NumValidators; i++ {
		p, err := frost.NewDkgParticipant(
			uint32(shareIdx),
			uint32(def.Threshold),
			randomNumber(random),
			curves.BLS12381G1(),
			otherIDs...)
		if err != nil {
			return nil, errors.Wrap(err, "new participant")
		}

		resp = append(resp, p)
	}

	return resp, nil
}

// randomNumber return a random 8 byte number as a string.
func randomNumber(random io.Reader) string {
	var bytes [8]byte
	_, _ = random.Read(bytes[:])
	i := binary.BigEndian.Uint64(bytes[:])

	return strconv.FormatUint(i, 10)
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
