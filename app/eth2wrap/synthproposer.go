// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	shuffle "github.com/protolambda/eth2-shuffle"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
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
	eth2client.ValidatorsProvider
	eth2client.SlotsPerEpochProvider
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
func (h *synthWrapper) ProposerDuties(ctx context.Context, epoch eth2p0.Epoch, _ []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
	// TODO(corver): Should we support fetching duties for other validators not in the cluster?
	return h.synthProposerCache.Duties(ctx, h.Client, epoch)
}

func (h *synthWrapper) SubmitProposalPreparations(ctx context.Context, preparations []*eth2v1.ProposalPreparation) error {
	h.setFeeRecipients(preparations)

	return h.Client.SubmitProposalPreparations(ctx, preparations)
}

// BeaconBlockProposal returns an unsigned beacon block, possibly marked as synthetic.
func (h *synthWrapper) BeaconBlockProposal(ctx context.Context, slot eth2p0.Slot, randao eth2p0.BLSSignature, graffiti []byte) (*spec.VersionedBeaconBlock, error) {
	vIdx, ok, err := h.synthProposerCache.SyntheticVIdx(ctx, h.Client, slot)
	if err != nil {
		return nil, err
	} else if !ok {
		return h.Client.BeaconBlockProposal(ctx, slot, randao, graffiti)
	}

	return h.syntheticBlock(ctx, slot, vIdx)
}

// BlindedBeaconBlockProposal returns an unsigned blinded beacon block, possibly marked as synthetic.
func (h *synthWrapper) BlindedBeaconBlockProposal(ctx context.Context, slot eth2p0.Slot, randao eth2p0.BLSSignature, graffiti []byte) (*api.VersionedBlindedBeaconBlock, error) {
	vIdx, ok, err := h.synthProposerCache.SyntheticVIdx(ctx, h.Client, slot)
	if err != nil {
		return nil, err
	} else if !ok {
		return h.Client.BlindedBeaconBlockProposal(ctx, slot, randao, graffiti)
	}

	block, err := h.syntheticBlock(ctx, slot, vIdx)
	if err != nil {
		return nil, err
	}

	return blindedBlock(block)
}

// syntheticBlock returns a synthetic beacon block to propose.
func (h *synthWrapper) syntheticBlock(ctx context.Context, slot eth2p0.Slot, vIdx eth2p0.ValidatorIndex) (*spec.VersionedBeaconBlock, error) {
	var signedBlock *spec.VersionedSignedBeaconBlock

	// Work our way back from previous slot to find a block to base the synthetic block on.
	for prev := slot - 1; prev > 0; prev-- {
		signed, err := h.Client.SignedBeaconBlock(ctx, fmt.Sprint(prev))
		if err != nil {
			return nil, err
		} else if signed == nil { // go-eth2-client returns nil if block is not found.
			continue
		}

		signedBlock = signed

		break
	}

	if signedBlock == nil {
		return nil, errors.New("no block found to base synthetic block on")
	}

	// Convert signed block into unsigned block with synthetic graffiti and correct slot.

	feeRecipient := h.getFeeRecipient(vIdx)

	block := &spec.VersionedBeaconBlock{Version: signedBlock.Version}

	switch signedBlock.Version {
	case spec.DataVersionPhase0:
		block.Phase0 = signedBlock.Phase0.Message
		block.Phase0.Body.Graffiti = GetSyntheticGraffiti()
		block.Phase0.Slot = slot
		block.Phase0.ProposerIndex = vIdx
	case spec.DataVersionAltair:
		block.Altair = signedBlock.Altair.Message
		block.Altair.Body.Graffiti = GetSyntheticGraffiti()
		block.Altair.Slot = slot
		block.Altair.ProposerIndex = vIdx
	case spec.DataVersionBellatrix:
		block.Bellatrix = signedBlock.Bellatrix.Message
		block.Bellatrix.Body.Graffiti = GetSyntheticGraffiti()
		block.Bellatrix.Slot = slot
		block.Bellatrix.ProposerIndex = vIdx
		block.Bellatrix.Body.ExecutionPayload.FeeRecipient = feeRecipient
		block.Bellatrix.Body.ExecutionPayload.Transactions = fraction(block.Bellatrix.Body.ExecutionPayload.Transactions)
	case spec.DataVersionCapella:
		block.Capella = signedBlock.Capella.Message
		block.Capella.Body.Graffiti = GetSyntheticGraffiti()
		block.Capella.Slot = slot
		block.Capella.ProposerIndex = vIdx
		block.Capella.Body.ExecutionPayload.FeeRecipient = feeRecipient
		block.Capella.Body.ExecutionPayload.Transactions = fraction(block.Capella.Body.ExecutionPayload.Transactions)
	default:
		return nil, errors.New("unsupported block version")
	}

	return block, nil
}

// fraction returns a fraction of the transactions in the block.
// This is used to reduce the size of synthetic blocks to manageable levels.
func fraction(transactions []bellatrix.Transaction) []bellatrix.Transaction {
	return transactions[:len(transactions)/syntheticBlockFraction]
}

// SubmitBlindedBeaconBlock submits a blinded beacon block or swallows it if marked as synthetic.
func (h *synthWrapper) SubmitBlindedBeaconBlock(ctx context.Context, block *api.VersionedSignedBlindedBeaconBlock) error {
	if IsSyntheticBlindedBlock(block) {
		log.Debug(ctx, "Synthetic blinded beacon block swallowed")
		return nil
	}

	return h.Client.SubmitBlindedBeaconBlock(ctx, block)
}

// SubmitBeaconBlock submits a beacon block or swallows it if marked as synthetic.
func (h *synthWrapper) SubmitBeaconBlock(ctx context.Context, block *spec.VersionedSignedBeaconBlock) error {
	if IsSyntheticBlock(block) {
		log.Debug(ctx, "Synthetic beacon block swallowed")
		return nil
	}

	return h.Client.SubmitBeaconBlock(ctx, block)
}

// GetSyntheticGraffiti returns the graffiti used to mark synthetic blocks.
func GetSyntheticGraffiti() [32]byte {
	var synthGraffiti [32]byte
	copy(synthGraffiti[:], syntheticBlockGraffiti)

	return synthGraffiti
}

// IsSyntheticBlindedBlock returns true if the blinded block is a synthetic block.
func IsSyntheticBlindedBlock(block *api.VersionedSignedBlindedBeaconBlock) bool {
	var graffiti [32]byte
	switch block.Version {
	case spec.DataVersionBellatrix:
		graffiti = block.Bellatrix.Message.Body.Graffiti
	case spec.DataVersionCapella:
		graffiti = block.Capella.Message.Body.Graffiti
	default:
		return false
	}

	return graffiti == GetSyntheticGraffiti()
}

// IsSyntheticBlock returns true if the block is a synthetic block.
func IsSyntheticBlock(block *spec.VersionedSignedBeaconBlock) bool {
	var graffiti [32]byte
	switch block.Version {
	case spec.DataVersionPhase0:
		graffiti = block.Phase0.Message.Body.Graffiti
	case spec.DataVersionAltair:
		graffiti = block.Altair.Message.Body.Graffiti
	case spec.DataVersionBellatrix:
		graffiti = block.Bellatrix.Message.Body.Graffiti
	case spec.DataVersionCapella:
		graffiti = block.Capella.Message.Body.Graffiti
	default:
		return false
	}

	return graffiti == GetSyntheticGraffiti()
}

// synthProposerCache returns a new cache for synthetic proposer duties.
func newSynthProposerCache(pubkeys []eth2p0.BLSPubKey) *synthProposerCache {
	return &synthProposerCache{
		pubkeys:     pubkeys,
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
	pubkeys []eth2p0.BLSPubKey
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

	// Get active validators for the epoch
	// TODO(corver): Use cache instead of using head to try to mitigate this expensive call.
	vals, err := eth2Cl.ValidatorsByPubKey(ctx, "head", c.pubkeys)
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

	// Get slotsPerEpoch and the starting slot of the epoch.
	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(ctx)
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

		synthSlots[synthSlot] = valIdx
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

// SyntheticVIdx returns the validator index and true if the slot is a synthetic proposer duty.
func (c *synthProposerCache) SyntheticVIdx(ctx context.Context, eth2Cl synthProposerEth2Provider, slot eth2p0.Slot) (eth2p0.ValidatorIndex, bool, error) {
	// Get the epoch.
	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(ctx)
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

// blindedBlock converts a normal block into a blinded block.
func blindedBlock(block *spec.VersionedBeaconBlock) (*api.VersionedBlindedBeaconBlock, error) {
	var resp *api.VersionedBlindedBeaconBlock
	// Blinded blocks are only available from bellatrix.
	switch block.Version {
	case spec.DataVersionBellatrix:
		resp = &api.VersionedBlindedBeaconBlock{
			Version: block.Version,
			Bellatrix: &eth2bellatrix.BlindedBeaconBlock{
				Slot:          block.Bellatrix.Slot,
				ProposerIndex: block.Bellatrix.ProposerIndex,
				ParentRoot:    block.Bellatrix.ParentRoot,
				StateRoot:     block.Bellatrix.StateRoot,
				Body: &eth2bellatrix.BlindedBeaconBlockBody{
					RANDAOReveal:      block.Bellatrix.Body.RANDAOReveal,
					ETH1Data:          block.Bellatrix.Body.ETH1Data,
					Graffiti:          block.Bellatrix.Body.Graffiti,
					ProposerSlashings: block.Bellatrix.Body.ProposerSlashings,
					AttesterSlashings: block.Bellatrix.Body.AttesterSlashings,
					Attestations:      block.Bellatrix.Body.Attestations,
					Deposits:          block.Bellatrix.Body.Deposits,
					VoluntaryExits:    block.Bellatrix.Body.VoluntaryExits,
					SyncAggregate:     block.Bellatrix.Body.SyncAggregate,
					ExecutionPayloadHeader: &bellatrix.ExecutionPayloadHeader{
						ParentHash:       block.Bellatrix.Body.ExecutionPayload.ParentHash,
						FeeRecipient:     block.Bellatrix.Body.ExecutionPayload.FeeRecipient,
						StateRoot:        block.Bellatrix.Body.ExecutionPayload.StateRoot,
						ReceiptsRoot:     block.Bellatrix.Body.ExecutionPayload.ReceiptsRoot,
						LogsBloom:        block.Bellatrix.Body.ExecutionPayload.LogsBloom,
						PrevRandao:       block.Bellatrix.Body.ExecutionPayload.PrevRandao,
						BlockNumber:      block.Bellatrix.Body.ExecutionPayload.BlockNumber,
						GasLimit:         block.Bellatrix.Body.ExecutionPayload.GasLimit,
						GasUsed:          block.Bellatrix.Body.ExecutionPayload.GasUsed,
						Timestamp:        block.Bellatrix.Body.ExecutionPayload.Timestamp,
						ExtraData:        block.Bellatrix.Body.ExecutionPayload.ExtraData,
						BaseFeePerGas:    block.Bellatrix.Body.ExecutionPayload.BaseFeePerGas,
						BlockHash:        block.Bellatrix.Body.ExecutionPayload.BlockHash,
						TransactionsRoot: eth2p0.Root{}, // Use empty root.
					},
				},
			},
		}
	case spec.DataVersionCapella:
		resp = &api.VersionedBlindedBeaconBlock{
			Version: block.Version,
			Capella: &eth2capella.BlindedBeaconBlock{
				Slot:          block.Capella.Slot,
				ProposerIndex: block.Capella.ProposerIndex,
				ParentRoot:    block.Capella.ParentRoot,
				StateRoot:     block.Capella.StateRoot,
				Body: &eth2capella.BlindedBeaconBlockBody{
					RANDAOReveal:      block.Capella.Body.RANDAOReveal,
					ETH1Data:          block.Capella.Body.ETH1Data,
					Graffiti:          block.Capella.Body.Graffiti,
					ProposerSlashings: block.Capella.Body.ProposerSlashings,
					AttesterSlashings: block.Capella.Body.AttesterSlashings,
					Attestations:      block.Capella.Body.Attestations,
					Deposits:          block.Capella.Body.Deposits,
					VoluntaryExits:    block.Capella.Body.VoluntaryExits,
					SyncAggregate:     block.Capella.Body.SyncAggregate,
					ExecutionPayloadHeader: &capella.ExecutionPayloadHeader{
						ParentHash:       block.Capella.Body.ExecutionPayload.ParentHash,
						FeeRecipient:     block.Capella.Body.ExecutionPayload.FeeRecipient,
						StateRoot:        block.Capella.Body.ExecutionPayload.StateRoot,
						ReceiptsRoot:     block.Capella.Body.ExecutionPayload.ReceiptsRoot,
						LogsBloom:        block.Capella.Body.ExecutionPayload.LogsBloom,
						PrevRandao:       block.Capella.Body.ExecutionPayload.PrevRandao,
						BlockNumber:      block.Capella.Body.ExecutionPayload.BlockNumber,
						GasLimit:         block.Capella.Body.ExecutionPayload.GasLimit,
						GasUsed:          block.Capella.Body.ExecutionPayload.GasUsed,
						Timestamp:        block.Capella.Body.ExecutionPayload.Timestamp,
						ExtraData:        block.Capella.Body.ExecutionPayload.ExtraData,
						BaseFeePerGas:    block.Capella.Body.ExecutionPayload.BaseFeePerGas,
						BlockHash:        block.Capella.Body.ExecutionPayload.BlockHash,
						TransactionsRoot: eth2p0.Root{}, // Use empty root.
					},
				},
			},
		}
	default:
		return nil, errors.New("unsupported blinded block version")
	}

	return resp, nil
}
