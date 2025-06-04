// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tracker

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

const (
	// InclCheckLag is the number of slots to lag before checking inclusion.
	// We wait for 6 slots to mitigate against reorgs as it should cover almost all reorg scenarios.
	// Reorgs of more than 6 slots are very rare in ethereum PoS.
	// The inclusion checker should begin checking for the inclusion of duties after the duty deadline is reached,
	// i.e., after 5 slots.
	InclCheckLag = 6

	// InclMissedLag is the number of slots after which we assume the duty was not included and we
	// delete cached submissions.
	InclMissedLag = 32
)

// subkey uniquely identifies a submission.
type subkey struct {
	Duty   core.Duty
	Pubkey core.PubKey
}

// submission represents a duty submitted to the beacon node/chain.
type submission struct {
	Duty   core.Duty
	Pubkey core.PubKey
	Data   core.SignedData
	Delay  time.Duration
}

// trackerInclFunc defines the tracker callback for the inclusion checker.
type trackerInclFunc func(core.Duty, core.PubKey, core.SignedData, error)

// inclSupported defines duty types for which inclusion checks are supported.
var inclSupported = map[core.DutyType]bool{
	core.DutyProposer: true,
}

// inclusionCore tracks the inclusion of submitted duties.
// It has a simplified API to allow for easy testing.
type inclusionCore struct {
	mu          sync.Mutex
	submissions map[subkey]submission

	trackerInclFunc trackerInclFunc
	missedFunc      func(context.Context, submission)
}

// Submitted is called when a duty is submitted to the beacon node.
// It adds the duty to the list of submitted duties.
func (i *inclusionCore) Submitted(duty core.Duty, pubkey core.PubKey, data core.SignedData, delay time.Duration) (err error) {
	if !inclSupported[duty.Type] {
		return nil
	}

	var (
		block core.VersionedSignedProposal
		ok    bool
	)

	block, ok = data.(core.VersionedSignedProposal)
	if !ok {
		return errors.New("invalid block")
	}

	defer func() {
		if r := recover(); r != nil {
			err = errors.New("could not determine if proposal was synthetic or not",
				z.Str("proposal", fmt.Sprintf("%+v", block)),
				z.Bool("blinded", block.Blinded),
			)
		}
	}()

	//nolint: gocritic // Prefer clearer separation of blinded <-> unblinded.
	if block.Blinded {
		blinded, err := block.ToBlinded()
		if err != nil {
			return errors.Wrap(err, "expected blinded proposal")
		}

		if eth2wrap.IsSyntheticBlindedBlock(&blinded) {
			// Report inclusion for synthetic blocks as it is already included on-chain.
			i.trackerInclFunc(duty, pubkey, data, nil)

			return nil
		}
	} else {
		if eth2wrap.IsSyntheticProposal(&block.VersionedSignedProposal) {
			// Report inclusion for synthetic blocks as it is already included on-chain.
			i.trackerInclFunc(duty, pubkey, data, nil)

			return nil
		}
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	key := subkey{Duty: duty, Pubkey: pubkey}
	i.submissions[key] = submission{
		Duty:   duty,
		Pubkey: pubkey,
		Data:   data,
		Delay:  delay,
	}

	return err
}

// Trim removes all duties that are older than the specified slot.
// It also calls the missedFunc for any duties that have not been included.
func (i *inclusionCore) Trim(ctx context.Context, slot uint64) {
	i.mu.Lock()
	defer i.mu.Unlock()

	// Trim submissions
	for key, sub := range i.submissions {
		if sub.Duty.Slot > slot {
			continue
		}

		// Report missed and trim
		i.missedFunc(ctx, sub)
		i.trackerInclFunc(sub.Duty, sub.Pubkey, sub.Data, errors.New("duty not included on-chain"))

		delete(i.submissions, key)
	}
}

// CheckBlock checks whether the block includes any of the submitted duties.
func (i *inclusionCore) CheckBlock(ctx context.Context, slot uint64, found bool) {
	i.mu.Lock()
	defer i.mu.Unlock()

	for key, sub := range i.submissions {
		switch sub.Duty.Type {
		case core.DutyProposer:
			if sub.Duty.Slot != slot {
				continue
			}

			proposal, ok := sub.Data.(core.VersionedSignedProposal)
			if !ok {
				log.Error(ctx, "Submission data has wrong type", nil, z.Str("type", fmt.Sprintf("%T", sub.Data)))
				continue
			}

			if found {
				var msg string
				msg = "Broadcasted block included on-chain"
				if proposal.Blinded {
					msg = "Broadcasted blinded block included on-chain"
				}
				log.Info(ctx, msg,
					z.U64("block_slot", slot),
					z.Any("pubkey", sub.Pubkey),
					z.Any("broadcast_delay", sub.Delay),
				)
			} else {
				i.missedFunc(ctx, sub)
			}

			// Just report block inclusions to tracker and trim
			i.trackerInclFunc(sub.Duty, sub.Pubkey, sub.Data, nil)
			delete(i.submissions, key)
		default:
			panic("bug: unexpected type") // Sanity check, this should never happen
		}
	}
}

// reportMissed reports duties that were broadcast but never included on chain.
func reportMissed(ctx context.Context, sub submission) {
	inclusionMisses.WithLabelValues(sub.Duty.Type.String()).Inc()

	switch sub.Duty.Type {
	case core.DutyProposer:
		proposal, ok := sub.Data.(core.VersionedSignedProposal)
		if !ok {
			log.Error(ctx, "Submission data has wrong type", nil, z.Str("type", fmt.Sprintf("%T", sub.Data)))
		} else {
			msg := "Broadcasted block never included on-chain"
			if proposal.Blinded {
				msg = "Broadcasted blinded block never included on-chain"
			}

			log.Warn(ctx, msg, nil,
				z.Any("pubkey", sub.Pubkey),
				z.U64("block_slot", sub.Duty.Slot),
				z.Any("broadcast_delay", sub.Delay),
			)
		}
	default:
		panic("bug: unexpected type") // Sanity check, this should never happen
	}
}

// NewInclusion returns a new InclusionChecker.
func NewInclusion(ctx context.Context, eth2Cl eth2wrap.Client, trackerInclFunc trackerInclFunc) (*InclusionChecker, error) {
	genesisTime, err := eth2wrap.FetchGenesisTime(ctx, eth2Cl)
	if err != nil {
		return nil, err
	}
	slotDuration, _, err := eth2wrap.FetchSlotsConfig(ctx, eth2Cl)
	if err != nil {
		return nil, errors.Wrap(err, "fetch slots config")
	}

	inclCore := &inclusionCore{
		missedFunc:      reportMissed,
		trackerInclFunc: trackerInclFunc,
		submissions:     make(map[subkey]submission),
	}

	return &InclusionChecker{
		core:           inclCore,
		eth2Cl:         eth2Cl,
		genesis:        genesisTime,
		slotDuration:   slotDuration,
		checkBlockFunc: inclCore.CheckBlock,
	}, nil
}

// InclusionChecker checks whether duties have been included on-chain.
type InclusionChecker struct {
	genesis        time.Time
	slotDuration   time.Duration
	eth2Cl         eth2wrap.Client
	core           *inclusionCore
	checkBlockFunc func(ctx context.Context, slot uint64, found bool) // Alises for testing
}

// Submitted is called when a duty has been submitted.
func (a *InclusionChecker) Submitted(duty core.Duty, set core.SignedDataSet) error {
	slotStart := a.genesis.Add(a.slotDuration * time.Duration(duty.Slot))

	for key, data := range set {
		if err := a.core.Submitted(duty, key, data, time.Since(slotStart)); err != nil {
			return err
		}
	}

	return nil
}

func (a *InclusionChecker) Run(ctx context.Context) {
	ctx = log.WithTopic(ctx, "tracker")

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var checkedSlot uint64

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			slot := uint64(time.Since(a.genesis)/a.slotDuration) - InclCheckLag
			if checkedSlot == slot {
				continue
			}
			if err := a.checkBlock(ctx, slot); err != nil {
				log.Warn(ctx, "Failed to check inclusion", err, z.U64("slot", slot))
				continue
			}

			checkedSlot = slot
			a.core.Trim(ctx, slot-InclMissedLag)
		}
	}
}

func (a *InclusionChecker) checkBlock(ctx context.Context, slot uint64) error {
	block, err := a.eth2Cl.Block(ctx, strconv.FormatUint(slot, 10))
	if err != nil {
		return err
	}
	var found bool
	if block != nil {
		found = true
	} else {
		found = false
	}

	a.checkBlockFunc(ctx, slot, found)

	return nil
}
