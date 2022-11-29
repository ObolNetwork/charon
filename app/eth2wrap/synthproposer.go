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

package eth2wrap

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	shuffle "github.com/protolambda/eth2-shuffle"
)

// maxCachedEpochs limits the amount of epochs to cache.
const maxCachedEpochs = 10

type synthProposerEth2Provider interface {
	eth2client.ValidatorsProvider
	eth2client.SlotsPerEpochProvider
	eth2client.ProposerDutiesProvider
}

// synthProposerCache returns a new cache for synthetic proposer duties.
func newSynthProposerCache(pubkeys []eth2p0.BLSPubKey) *synthProposerCache {
	return &synthProposerCache{
		pubkeys:     pubkeys,
		duties:      make(map[eth2p0.Epoch][]*eth2v1.ProposerDuty),
		synths:      make(map[eth2p0.Epoch]map[eth2p0.Slot]bool),
		shuffleFunc: eth2Shuffle,
	}
}

// synthProposerCache caches actual and synthetic proposer duties for the set of public keys.
//
// Since only a single validator can be a proposer per slot, we require all
// validators to calculate the synthetic duties for the whole set.
type synthProposerCache struct {
	pubkeys []eth2p0.BLSPubKey
	// shuffleFunc deterministically shuffles the validator indices for the epoch.
	shuffleFunc func(eth2p0.Epoch, []eth2p0.ValidatorIndex) []eth2p0.ValidatorIndex

	mu     sync.RWMutex
	fifo   []eth2p0.Epoch
	duties map[eth2p0.Epoch][]*eth2v1.ProposerDuty
	synths map[eth2p0.Epoch]map[eth2p0.Slot]bool
}

// Duties returns the upstream and synthetic duties for all pubkeys for the provided epoch.
func (c *synthProposerCache) Duties(ctx context.Context, eth2Cl synthProposerEth2Provider, epoch eth2p0.Epoch) ([]*eth2v1.ProposerDuty, error) {
	// Check if cache already populated for this epoch using read lock.
	c.mu.RLock()
	duties, ok := c.duties[epoch]
	c.mu.RUnlock()
	if ok {
		return duties, nil
	}

	// Get slotsPerEpoch and the starting slot of the epoch.
	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return nil, err
	}

	epochSlot := eth2p0.Slot(epoch) * eth2p0.Slot(slotsPerEpoch)

	// Get active validators for the epoch
	vals, err := eth2Cl.ValidatorsByPubKey(ctx, fmt.Sprint(epochSlot), c.pubkeys)
	if err != nil {
		return nil, err
	}

	var activeIdxs []eth2p0.ValidatorIndex
	for _, val := range vals {
		if !val.Status.IsActive() {
			continue
		}
		activeIdxs = append(activeIdxs, val.Index)
	}

	// Get actual duties for all validators for the epoch.
	duties, err = eth2Cl.ProposerDuties(ctx, epoch, activeIdxs)
	if err != nil {
		return nil, err
	}

	// Mark those not requiring synthetic duties.
	noSynth := make(map[eth2p0.ValidatorIndex]bool)
	for _, duty := range duties {
		noSynth[duty.ValidatorIndex] = true
	}

	// Deterministic synthetic duties for the rest.
	synthSlots := make(map[eth2p0.Slot]bool)
	for _, valIdx := range c.shuffleFunc(epoch, activeIdxs) {
		if noSynth[valIdx] {
			continue
		}

		offset := eth2p0.Slot(valIdx) % eth2p0.Slot(slotsPerEpoch)
		synthSlot := epochSlot + offset
		if _, ok := synthSlots[synthSlot]; ok {
			// We already have a synth proposer for this slot.
			continue
		}

		synthSlots[synthSlot] = true
		duties = append(duties, &eth2v1.ProposerDuty{
			PubKey:         vals[valIdx].Validator.PublicKey,
			Slot:           synthSlot,
			ValidatorIndex: valIdx,
		})
	}

	// Cache the values for the epoch
	c.mu.Lock()
	defer c.mu.Unlock()

	c.fifo = append(c.fifo, epoch)
	c.duties[epoch] = duties
	c.synths[epoch] = synthSlots

	// Trim the cache
	if len(c.fifo) > maxCachedEpochs {
		delete(c.duties, c.fifo[0])
		delete(c.synths, c.fifo[0])
		c.fifo = c.fifo[1:]
	}

	return duties, nil
}

// IsSynthetic returns true if the slot is a synthetic proposer duty.
func (c *synthProposerCache) IsSynthetic(ctx context.Context, eth2Cl synthProposerEth2Provider, slot eth2p0.Slot) (bool, error) {
	// Get the epoch.
	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return false, err
	}
	epoch := eth2p0.Epoch(slot) / eth2p0.Epoch(slotsPerEpoch)

	// Ensure that cache is populated.
	_, err = c.Duties(ctx, eth2Cl, epoch)
	if err != nil {
		return false, err
	}

	// Return the result.
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.synths[epoch][slot], nil
}

// eth2Shuffle is the eth2 pseudo-random (deterministic) shuffle function.
func eth2Shuffle(epoch eth2p0.Epoch, indices []eth2p0.ValidatorIndex) []eth2p0.ValidatorIndex {
	var uints []uint64
	for _, i := range indices {
		uints = append(uints, uint64(i))
	}

	// Use little endian epoch as the seed.
	var seed [32]byte
	binary.LittleEndian.PutUint64(seed[:], uint64(epoch))

	const rounds = 90 // From https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#misc-1

	shuffle.ShuffleList(getStandardHashFn(), uints, rounds, seed)

	var resp []eth2p0.ValidatorIndex
	for _, i := range uints {
		resp = append(resp, eth2p0.ValidatorIndex(i))
	}

	return resp
}

// getStandardHashFn returns a standard sha256 hash function as per
// https://github.com/protolambda/eth2-shuffle/blob/master/test_util.go.
func getStandardHashFn() shuffle.HashFn {
	hash := sha256.New()
	hashFn := func(in []byte) []byte {
		hash.Reset()
		hash.Write(in)

		return hash.Sum(nil)
	}

	return hashFn
}
