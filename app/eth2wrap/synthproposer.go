// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/http"
	"sync"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	eth2fulu "github.com/attestantio/go-eth2-client/api/v1/fulu"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	shuffle "github.com/protolambda/eth2-shuffle"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

const (
	// maxCachedEpochs limits the amount of epochs to cache.
	maxCachedEpochs = 10
	// syntheticBlockGraffiti defines the graffiti to identify synthetic blocks.
	syntheticBlockGraffiti = "SYNTHETIC BLOCK: DO NOT SUBMIT"

	// syntheticBlockFraction is the fraction 1/Nth of transactions to include in a synthetic block.
	// This decreases synthetic block size to manageable levels.
	syntheticBlockFraction = 10
)

type synthProposerEth2Provider interface {
	CachedValidatorsProvider
	eth2client.SpecProvider
	eth2client.ProposerDutiesProvider
}

var _ Client = &synthWrapper{}

// synthWrapper wraps an eth2 client and provides synthetic proposer duties.
type synthWrapper struct {
	Client

	synthProposerCache *synthProposerCache

	mu            sync.RWMutex
	feeRecipients map[eth2p0.ValidatorIndex]bellatrix.ExecutionAddress
}

// setFeeRecipients caches the provided fee recipients.
func (h *synthWrapper) setFeeRecipients(preparations []*eth2v1.ProposalPreparation) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, preparation := range preparations {
		h.feeRecipients[preparation.ValidatorIndex] = preparation.FeeRecipient
	}
}

// getFeeRecipient returns the fee recipient for the provided validator index.
func (h *synthWrapper) getFeeRecipient(vIdx eth2p0.ValidatorIndex) bellatrix.ExecutionAddress {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.feeRecipients[vIdx]
}

// ProposerDuties returns upstream proposer duties for the provided validator indexes or
// upstream proposer duties and synthetic duties for all cluster validators if enabled.
func (h *synthWrapper) ProposerDuties(ctx context.Context, opts *eth2api.ProposerDutiesOpts) (*eth2api.Response[[]*eth2v1.ProposerDuty], error) {
	duties, err := h.synthProposerCache.Duties(ctx, h.Client, opts.Epoch)
	if err != nil {
		return nil, err
	}

	return wrapResponse(duties), nil
}

func (h *synthWrapper) SubmitProposalPreparations(ctx context.Context, preparations []*eth2v1.ProposalPreparation) error {
	h.setFeeRecipients(preparations)

	return h.Client.SubmitProposalPreparations(ctx, preparations)
}

// Proposal returns an unsigned beacon block proposal, possibly marked as synthetic.
func (h *synthWrapper) Proposal(ctx context.Context, opts *eth2api.ProposalOpts) (*eth2api.Response[*eth2api.VersionedProposal], error) {
	vIdx, ok, err := h.synthProposerCache.SyntheticVIdx(ctx, h.Client, opts.Slot)
	if err != nil {
		return nil, err
	} else if !ok {
		resp, err := h.Client.Proposal(ctx, opts)
		if err != nil {
			return nil, errors.Wrap(err, "propose beacon proposal")
		}

		return resp, nil
	}

	proposal, err := h.syntheticProposal(ctx, opts.Slot, vIdx)
	if err != nil {
		return nil, err
	}

	return wrapResponse(proposal), nil
}

// syntheticProposal returns a synthetic unsigned beacon block to propose.
func (h *synthWrapper) syntheticProposal(ctx context.Context, slot eth2p0.Slot, vIdx eth2p0.ValidatorIndex) (*eth2api.VersionedProposal, error) {
	var signedBlock *eth2spec.VersionedSignedBeaconBlock

	// Work our way back from previous slot to find a block to base the synthetic proposal on.
	for prev := slot - 1; prev > 0; prev-- {
		opts := &eth2api.SignedBeaconBlockOpts{
			Block: fmt.Sprint(prev),
		}

		signed, err := h.SignedBeaconBlock(ctx, opts)
		if err != nil {
			if z.ContainsField(err, z.Int("status_code", http.StatusNotFound)) {
				continue
			}

			return nil, err
		}

		signedBlock = signed.Data

		break
	}

	if signedBlock == nil {
		return nil, errors.New("no proposal found to base synthetic proposal on")
	}

	// Convert signed proposal into unsigned proposal with synthetic graffiti and correct slot.

	feeRecipient := h.getFeeRecipient(vIdx)

	proposal := &eth2api.VersionedProposal{Version: signedBlock.Version}
	switch signedBlock.Version {
	case eth2spec.DataVersionPhase0:
		proposal.Phase0 = signedBlock.Phase0.Message
		proposal.Phase0.Body.Graffiti = GetSyntheticGraffiti()
		proposal.Phase0.Slot = slot
		proposal.Phase0.ProposerIndex = vIdx
	case eth2spec.DataVersionAltair:
		proposal.Altair = signedBlock.Altair.Message
		proposal.Altair.Body.Graffiti = GetSyntheticGraffiti()
		proposal.Altair.Slot = slot
		proposal.Altair.ProposerIndex = vIdx
	case eth2spec.DataVersionBellatrix:
		proposal.Bellatrix = signedBlock.Bellatrix.Message
		proposal.Bellatrix.Body.Graffiti = GetSyntheticGraffiti()
		proposal.Bellatrix.Slot = slot
		proposal.Bellatrix.ProposerIndex = vIdx
		proposal.Bellatrix.Body.ExecutionPayload.FeeRecipient = feeRecipient
		proposal.Bellatrix.Body.ExecutionPayload.Transactions = fraction(proposal.Bellatrix.Body.ExecutionPayload.Transactions)
	case eth2spec.DataVersionCapella:
		proposal.Capella = signedBlock.Capella.Message
		proposal.Capella.Body.Graffiti = GetSyntheticGraffiti()
		proposal.Capella.Slot = slot
		proposal.Capella.ProposerIndex = vIdx
		proposal.Capella.Body.ExecutionPayload.FeeRecipient = feeRecipient
		proposal.Capella.Body.ExecutionPayload.Transactions = fraction(proposal.Capella.Body.ExecutionPayload.Transactions)
	case eth2spec.DataVersionDeneb:
		proposal.Deneb = &eth2deneb.BlockContents{}
		proposal.Deneb.Block = signedBlock.Deneb.Message
		proposal.Deneb.Block.Body.Graffiti = GetSyntheticGraffiti()
		proposal.Deneb.Block.Slot = slot
		proposal.Deneb.Block.ProposerIndex = vIdx
		proposal.Deneb.Block.Body.ExecutionPayload.FeeRecipient = feeRecipient
		proposal.Deneb.Block.Body.ExecutionPayload.Transactions = fraction(proposal.Deneb.Block.Body.ExecutionPayload.Transactions)
	case eth2spec.DataVersionElectra:
		proposal.Electra = &eth2electra.BlockContents{}
		proposal.Electra.Block = signedBlock.Electra.Message
		proposal.Electra.Block.Body.Graffiti = GetSyntheticGraffiti()
		proposal.Electra.Block.Slot = slot
		proposal.Electra.Block.ProposerIndex = vIdx
		proposal.Electra.Block.Body.ExecutionPayload.FeeRecipient = feeRecipient
		proposal.Electra.Block.Body.ExecutionPayload.Transactions = fraction(proposal.Electra.Block.Body.ExecutionPayload.Transactions)
	case eth2spec.DataVersionFulu:
		proposal.Fulu = &eth2fulu.BlockContents{}
		proposal.Fulu.Block = signedBlock.Fulu.Message
		proposal.Fulu.Block.Body.Graffiti = GetSyntheticGraffiti()
		proposal.Fulu.Block.Slot = slot
		proposal.Fulu.Block.ProposerIndex = vIdx
		proposal.Fulu.Block.Body.ExecutionPayload.FeeRecipient = feeRecipient
		proposal.Fulu.Block.Body.ExecutionPayload.Transactions = fraction(proposal.Fulu.Block.Body.ExecutionPayload.Transactions)
	default:
		return nil, errors.New("unsupported proposal version")
	}

	return proposal, nil
}

// fraction returns a fraction of the transactions in the block.
// This is used to reduce the size of synthetic blocks to manageable levels.
func fraction(transactions []bellatrix.Transaction) []bellatrix.Transaction {
	return transactions[:len(transactions)/syntheticBlockFraction]
}

// SubmitBlindedProposal submits a blinded beacon block proposal or swallows it if marked as synthetic.
func (h *synthWrapper) SubmitBlindedProposal(ctx context.Context, opts *eth2api.SubmitBlindedProposalOpts) error {
	if IsSyntheticBlindedBlock(opts.Proposal) {
		log.Debug(ctx, "Synthetic blinded beacon proposal swallowed")
		return nil
	}

	return h.Client.SubmitBlindedProposal(ctx, opts)
}

// SubmitProposal submits a beacon block or swallows it if marked as synthetic.
func (h *synthWrapper) SubmitProposal(ctx context.Context, opts *eth2api.SubmitProposalOpts) error {
	if IsSyntheticProposal(opts.Proposal) {
		log.Debug(ctx, "Synthetic beacon block swallowed")
		return nil
	}

	return h.Client.SubmitProposal(ctx, opts)
}

// GetSyntheticGraffiti returns the graffiti used to mark synthetic blocks.
func GetSyntheticGraffiti() [32]byte {
	var synthGraffiti [32]byte
	copy(synthGraffiti[:], syntheticBlockGraffiti)

	return synthGraffiti
}

// IsSyntheticBlindedBlock returns true if the blinded block is a synthetic block.
func IsSyntheticBlindedBlock(block *eth2api.VersionedSignedBlindedProposal) bool {
	var graffiti [32]byte

	switch block.Version {
	case eth2spec.DataVersionBellatrix:
		graffiti = block.Bellatrix.Message.Body.Graffiti
	case eth2spec.DataVersionCapella:
		graffiti = block.Capella.Message.Body.Graffiti
	case eth2spec.DataVersionDeneb:
		graffiti = block.Deneb.Message.Body.Graffiti
	case eth2spec.DataVersionElectra:
		graffiti = block.Electra.Message.Body.Graffiti
	case eth2spec.DataVersionFulu:
		graffiti = block.Fulu.Message.Body.Graffiti
	default:
		return false
	}

	return graffiti == GetSyntheticGraffiti()
}

// IsSyntheticProposal returns true if the block is a synthetic block proposal.
func IsSyntheticProposal(block *eth2api.VersionedSignedProposal) bool {
	var graffiti [32]byte

	switch block.Version {
	case eth2spec.DataVersionPhase0:
		graffiti = block.Phase0.Message.Body.Graffiti
	case eth2spec.DataVersionAltair:
		graffiti = block.Altair.Message.Body.Graffiti
	case eth2spec.DataVersionBellatrix:
		graffiti = block.Bellatrix.Message.Body.Graffiti
	case eth2spec.DataVersionCapella:
		graffiti = block.Capella.Message.Body.Graffiti
	case eth2spec.DataVersionDeneb:
		graffiti = block.Deneb.SignedBlock.Message.Body.Graffiti
	case eth2spec.DataVersionElectra:
		graffiti = block.Electra.SignedBlock.Message.Body.Graffiti
	case eth2spec.DataVersionFulu:
		graffiti = block.Fulu.SignedBlock.Message.Body.Graffiti
	default:
		return false
	}

	return graffiti == GetSyntheticGraffiti()
}

// newSynthProposerCache returns a new cache for synthetic proposer duties.
func newSynthProposerCache() *synthProposerCache {
	return &synthProposerCache{
		duties:      make(map[eth2p0.Epoch][]*eth2v1.ProposerDuty),
		synths:      make(map[eth2p0.Epoch]map[eth2p0.Slot]eth2p0.ValidatorIndex),
		shuffleFunc: eth2Shuffle,
	}
}

// synthProposerCache caches actual and synthetic proposer duties for the set of public keys.
//
// Since only a single validator can be a proposer per slot, we require all
// validators to calculate the synthetic duties for the whole set.
type synthProposerCache struct {
	// shuffleFunc deterministically shuffles the validator indices for the epoch.
	shuffleFunc func(eth2p0.Epoch, []eth2p0.ValidatorIndex) []eth2p0.ValidatorIndex

	mu     sync.RWMutex
	fifo   []eth2p0.Epoch
	duties map[eth2p0.Epoch][]*eth2v1.ProposerDuty
	synths map[eth2p0.Epoch]map[eth2p0.Slot]eth2p0.ValidatorIndex
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

	vals, err := eth2Cl.ActiveValidators(ctx)
	if err != nil {
		return nil, err
	}

	// Get actual duties for all validators for the epoch.
	opts := &eth2api.ProposerDutiesOpts{
		Epoch:   epoch,
		Indices: vals.Indices(),
	}

	resp, err := eth2Cl.ProposerDuties(ctx, opts)
	if err != nil {
		return nil, err
	}

	duties = resp.Data

	_, slotsPerEpoch, err := FetchSlotsConfig(ctx, eth2Cl)
	if err != nil {
		return nil, err
	}

	epochSlot := eth2p0.Slot(epoch) * eth2p0.Slot(slotsPerEpoch)

	// Mark those not requiring synthetic duties.
	noSynth := make(map[eth2p0.ValidatorIndex]bool)
	for _, duty := range duties {
		noSynth[duty.ValidatorIndex] = true
	}

	// Deterministic synthetic duties for the rest.
	synthSlots := make(map[eth2p0.Slot]eth2p0.ValidatorIndex)

	for _, valIdx := range c.shuffleFunc(epoch, vals.Indices()) {
		if noSynth[valIdx] {
			continue
		}

		offset := eth2p0.Slot(valIdx) % eth2p0.Slot(slotsPerEpoch)

		synthSlot := epochSlot + offset
		if _, ok := synthSlots[synthSlot]; ok {
			// We already have a synth proposer for this slot.
			continue
		}

		synthSlots[synthSlot] = valIdx
		duties = append(duties, &eth2v1.ProposerDuty{
			PubKey:         vals[valIdx],
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

// SyntheticVIdx returns the validator index and true if the slot is a synthetic proposer duty.
func (c *synthProposerCache) SyntheticVIdx(ctx context.Context, eth2Cl synthProposerEth2Provider, slot eth2p0.Slot) (eth2p0.ValidatorIndex, bool, error) {
	_, slotsPerEpoch, err := FetchSlotsConfig(ctx, eth2Cl)
	if err != nil {
		return 0, false, err
	}

	epoch := eth2p0.Epoch(slot) / eth2p0.Epoch(slotsPerEpoch)

	// Ensure that cache is populated.
	_, err = c.Duties(ctx, eth2Cl, epoch)
	if err != nil {
		return 0, false, err
	}

	// Return the result.
	c.mu.RLock()
	defer c.mu.RUnlock()

	vIdx, ok := c.synths[epoch][slot]

	return vIdx, ok, nil
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
		_, _ = hash.Write(in)

		return hash.Sum(nil)
	}

	return hashFn
}

// wrapResponse wraps the provided data into an API Response and returns the response.
func wrapResponse[T any](data T) *eth2api.Response[T] {
	return &eth2api.Response[T]{Data: data}
}
