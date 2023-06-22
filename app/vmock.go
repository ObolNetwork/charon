// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/testutil/validatormock" // Allow testutil
)

// wireValidatorMock wires the validator mock if enabled. It connects via http validatorapi.Router.
func wireValidatorMock(conf Config, pubshares []eth2p0.BLSPubKey, sched core.Scheduler) error {
	if !conf.SimnetVMock {
		return nil
	}

	// Create stateful wrapper
	vMockWrap, err := newVMockWrapper(conf, pubshares)
	if err != nil {
		return err
	}

	onStartup := true
	sched.SubscribeSlots(func(ctx context.Context, slot core.Slot) error {
		// Prepare attestations when slots tick.
		vMockWrap(ctx, slot.Slot, func(ctx context.Context, state vMockState) error {
			return state.Attester.Prepare(ctx)
		})

		// Prepare sync committee message when epoch tick.
		if onStartup || slot.FirstInEpoch() {
			vMockWrap(ctx, slot.Slot, func(ctx context.Context, state vMockState) error {
				// Either call if it is first slot in epoch or on charon startup.
				return state.SyncCommMember.PrepareEpoch(ctx)
			})
		}

		// Submit validator registrations when epoch tick.
		if onStartup || slot.FirstInEpoch() {
			vMockWrap(ctx, slot.Slot, func(ctx context.Context, state vMockState) error {
				regs, err := validatormock.RegistrationsFromProposerConfig(ctx, state.Eth2Cl)
				if err != nil {
					return err
				}

				for pubshare, reg := range regs {
					err := validatormock.Register(ctx, state.Eth2Cl, state.SignFunc, reg, pubshare)
					if err != nil {
						return err
					}
				}

				return nil
			})
		}

		onStartup = false

		// Prepare sync committee selections when slots tick.
		vMockWrap(ctx, slot.Slot, func(ctx context.Context, state vMockState) error {
			// Either call if it is first slot in epoch or on charon startup.
			return state.SyncCommMember.PrepareSlot(ctx, eth2p0.Slot(slot.Slot))
		})

		// Submit sync committee message 1/3 into the slot.
		vMockWrap(ctx, slot.Slot, func(ctx context.Context, state vMockState) error {
			thirdDuration := slot.SlotDuration / 3
			thirdTime := slot.Time.Add(thirdDuration)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Until(thirdTime)):
				return state.SyncCommMember.Message(ctx, eth2p0.Slot(slot.Slot))
			}
		})

		return nil
	})

	// Handle duties when triggered.
	sched.SubscribeDuties(func(ctx context.Context, duty core.Duty, _ core.DutyDefinitionSet) error {
		vMockWrap(ctx, duty.Slot, func(ctx context.Context, state vMockState) error {
			return handleVMockDuty(ctx, duty, state.Eth2Cl, state.SignFunc, state.Attester, state.SyncCommMember)
		})

		return nil
	})

	return nil
}

// vMockState is the current validator mock state.
type vMockState struct {
	Eth2Cl         eth2wrap.Client
	SignFunc       validatormock.SignFunc
	Attester       *validatormock.SlotAttester // Changes every slot
	SyncCommMember *validatormock.SyncCommMember
}

// vMockCallback is a validator mock callback function that has access to the latest state.
type vMockCallback func(context.Context, vMockState) error

// newVMockWrapper returns a stateful validator mock wrapper function.
func newVMockWrapper(conf Config, pubshares []eth2p0.BLSPubKey,
) (func(ctx context.Context, slot int64, callback vMockCallback), error) {
	// Immutable state and providers.
	signFunc, err := newVMockSigner(conf, pubshares)
	if err != nil {
		return nil, err
	}

	eth2ClProvider := newVMockEth2Provider(conf)

	// Mutable state
	var (
		mu           sync.Mutex
		attesters    = make(map[eth2p0.Slot]*validatormock.SlotAttester)
		syncCommMems = make(map[eth2p0.Epoch]*validatormock.SyncCommMember)
	)

	// Trim state to avoid memory leak.
	const trimOffset = 2
	trim := func(slot eth2p0.Slot, epoch eth2p0.Epoch) {
		for s := range attesters {
			if s < slot-trimOffset {
				delete(attesters, s)
			}
		}

		for e := range syncCommMems {
			if e < epoch-trimOffset {
				delete(syncCommMems, e)
			}
		}
	}

	return func(ctx context.Context, slotInt int64, fn vMockCallback) {
		mu.Lock()
		defer mu.Unlock()

		ctx = log.WithTopic(ctx, "vmock")

		eth2Cl, err := eth2ClProvider()
		if err != nil {
			log.Error(ctx, "Failed creating mock eth2 client", err)
			return
		}

		slot := eth2p0.Slot(slotInt)
		epoch, err := eth2util.EpochFromSlot(ctx, eth2Cl, slot)
		if err != nil {
			log.Error(ctx, "Epoch from slot", err)
			return
		}

		// Get or create a slot attester for the slot
		attester, ok := attesters[slot]
		if !ok {
			attester = validatormock.NewSlotAttester(eth2Cl, slot, signFunc, pubshares)
			attesters[slot] = attester
		}

		// Get or create a sync committee member for the epoch
		syncCommMem, ok := syncCommMems[epoch]
		if !ok {
			syncCommMem = validatormock.NewSyncCommMember(eth2Cl, epoch, signFunc, pubshares)
			syncCommMems[epoch] = syncCommMem

			// Refresh validator cache on new epochs
			eth2Cl.SetValidatorCache(eth2wrap.NewValidatorCache(eth2Cl, pubshares).Get)
		}

		trim(slot, epoch)

		state := vMockState{
			Eth2Cl:         eth2Cl,
			SignFunc:       signFunc,
			Attester:       attester,
			SyncCommMember: syncCommMem,
		}

		// Validator mock calls are async
		go func() {
			ctx2, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()

			err := fn(ctx2, state)
			if err != nil && ctx.Err() == nil { // Only log if parent context wasn't closed.
				log.Error(ctx, "Validator mock error", err)
				return
			}
		}()
	}, nil
}

// newVMockEth2Provider returns a function that returns a cached validator mock eth2 client.
func newVMockEth2Provider(conf Config) func() (eth2wrap.Client, error) {
	var (
		cached eth2wrap.Client
		mu     sync.Mutex
	)

	const timeout = time.Second * 10

	return func() (eth2wrap.Client, error) {
		mu.Lock()
		defer mu.Unlock()

		if cached != nil {
			return cached, nil
		}

		// Try three times to reduce test startup issues.
		var err error
		for i := 0; i < 3; i++ {
			var eth2Svc eth2client.Service
			eth2Svc, err = eth2http.New(context.Background(),
				eth2http.WithLogLevel(1),
				eth2http.WithAddress("http://"+conf.ValidatorAPIAddr),
				eth2http.WithTimeout(timeout), // Allow sufficient time to block while fetching duties.
			)
			if err != nil {
				time.Sleep(time.Millisecond * 100) // Test startup backoff
				continue
			}
			eth2Http, ok := eth2Svc.(*eth2http.Service)
			if !ok {
				return nil, errors.New("invalid eth2 http service")
			}

			cached = eth2wrap.AdaptEth2HTTP(eth2Http, timeout)
		}

		return cached, err
	}
}

// newVMockSigner returns a validator mock sign function using keystore loaded from disk.
func newVMockSigner(conf Config, pubshares []eth2p0.BLSPubKey) (validatormock.SignFunc, error) {
	secrets := conf.TestConfig.SimnetKeys
	if len(secrets) == 0 {
		keyFiles, err := keystore.LoadFilesUnordered(conf.SimnetValidatorKeysDir)
		if err != nil {
			return nil, err
		}

		secrets, err = keyFiles.SequencedKeys()
		if err != nil {
			return nil, err
		}
	}

	signer, err := validatormock.NewSigner(secrets...)
	if err != nil {
		return nil, err
	}

	if len(secrets) == 0 && len(pubshares) != 0 {
		return nil, errors.New("validator mock keys empty")
	}
	if len(secrets) < len(pubshares) {
		return nil, errors.New("some validator mock keys missing", z.Int("expect", len(pubshares)), z.Int("found", len(secrets)))
	}
	for i, pubshare := range pubshares {
		_, err := signer(pubshare, []byte("test signing"))
		if err != nil {
			return nil, errors.Wrap(err, "validator mock key missing", z.Int("index", i))
		}
	}

	return signer, nil
}

// handleVMockDuty calls appropriate validator mock function for attestations, block proposals and sync committee contributions.
func handleVMockDuty(ctx context.Context, duty core.Duty, eth2Cl eth2wrap.Client,
	signer validatormock.SignFunc, attester *validatormock.SlotAttester,
	syncCommMember *validatormock.SyncCommMember,
) error {
	switch duty.Type {
	case core.DutyAttester:
		err := attester.Attest(ctx)
		if err != nil {
			return errors.Wrap(err, "mock attestation failed")
		}
		log.Info(ctx, "Mock attestation submitted to validatorapi", z.I64("slot", duty.Slot))
	case core.DutyAggregator:
		ok, err := attester.Aggregate(ctx)
		if err != nil {
			return errors.Wrap(err, "mock aggregation failed")
		} else if ok {
			log.Info(ctx, "Mock aggregation submitted to validatorapi", z.I64("slot", duty.Slot))
		}
	case core.DutyProposer:
		err := validatormock.ProposeBlock(ctx, eth2Cl, signer, eth2p0.Slot(duty.Slot))
		if err != nil {
			return errors.Wrap(err, "mock proposal failed")
		}
		log.Info(ctx, "Mock block proposal submitted to validatorapi", z.I64("slot", duty.Slot))
	case core.DutyBuilderProposer:
		err := validatormock.ProposeBlindedBlock(ctx, eth2Cl, signer, eth2p0.Slot(duty.Slot))
		if err != nil {
			return errors.Wrap(err, "mock builder proposal failed")
		}
		log.Info(ctx, "Mock blinded block proposal submitted to validatorapi", z.I64("slot", duty.Slot))
	case core.DutySyncContribution:
		ok, err := syncCommMember.Aggregate(ctx, eth2p0.Slot(duty.Slot))
		if err != nil {
			return errors.Wrap(err, "mock sync contribution failed")
		} else if ok {
			log.Info(ctx, "Mock sync contribution submitted to validatorapi", z.I64("slot", duty.Slot))
		}
	default:
		return errors.New("invalid duty type")
	}

	return nil
}
