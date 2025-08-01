// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/parsigdb"
	"github.com/obolnetwork/charon/core/parsigex"
	"github.com/obolnetwork/charon/p2p"
)

// Note: Following duty types shouldn't be confused with the duty types in core workflow. This was
// to get support from parsigex and parsigdb core components. This may subject to change when DKG
// package has its own networking and database components.
// Values of following constants should not change as it can break backwards compatibility.
type sigType int

const (
	// sigLock is responsible for lock hash signed partial signatures exchange and aggregation.
	sigLock sigType = 101
	// sigValidatorRegistration is responsible for the pre-generated validator registration exchange and aggregation.
	sigValidatorRegistration sigType = 102
	// sigDepositData is responsible for deposit data signed partial signatures exchange and aggregation.
	// For partial deposits, it increments the number for each unique partial amount, e.g. 201, 202, etc.
	sigDepositData sigType = 200
	// Do not add new values greater than sigDepositData.
)

// sigTypeStore is a shorthand for a map of sigType to map of core.PubKey to slice of core.ParSignedData.
type sigTypeStore map[sigType]map[core.PubKey][]core.ParSignedData

// dataByPubkey maps a sigType to its map of public key to slice of core.ParSignedData..
type dataByPubkey struct {
	store sigTypeStore
	lock  sync.Mutex
}

// exchanger is responsible for exchanging partial signatures between peers on libp2p.
type exchanger struct {
	sigex         *parsigex.ParSigEx
	sigdb         *parsigdb.MemDB
	sigTypes      map[sigType]bool
	sigData       dataByPubkey
	dutyGaterFunc func(duty core.Duty) bool
	sigDatasChan  chan map[core.PubKey][]core.ParSignedData
}

func newExchanger(p2pNode host.Host, peerIdx int, peers []peer.ID, sigTypes []sigType, timeout time.Duration) *exchanger {
	// Partial signature roots not known yet, so skip verification in parsigex, rather verify before we aggregate.
	noopVerifier := func(context.Context, core.Duty, core.PubKey, core.ParSignedData) error {
		return nil
	}

	st := make(map[sigType]bool)

	for _, sigType := range sigTypes {
		st[sigType] = true
	}

	dutyGaterFunc := func(duty core.Duty) bool {
		if duty.Type != core.DutySignature {
			return false
		}

		if slices.Contains(sigTypes, sigDepositData) && duty.Slot >= uint64(sigDepositData) {
			return true
		}

		return st[sigType(duty.Slot)]
	}

	ex := &exchanger{
		// threshold is len(peers) to wait until we get all the partial sigs from all the peers per DV
		sigdb:    parsigdb.NewMemDB(len(peers), noopDeadliner{}),
		sigex:    parsigex.NewParSigEx(p2pNode, p2p.Send, peerIdx, peers, noopVerifier, dutyGaterFunc, p2p.WithSendTimeout(timeout), p2p.WithReceiveTimeout(timeout)),
		sigTypes: st,
		sigData: dataByPubkey{
			store: sigTypeStore{},
			lock:  sync.Mutex{},
		},
		dutyGaterFunc: dutyGaterFunc,
		sigDatasChan:  make(chan map[core.PubKey][]core.ParSignedData, 1),
	}

	// Wiring core workflow components
	ex.sigdb.SubscribeInternal(ex.sigex.Broadcast)
	ex.sigdb.SubscribeThreshold(ex.pushPsigs)
	ex.sigex.Subscribe(ex.sigdb.StoreExternal)

	return ex
}

// exchange exhanges partial signatures of lockhash/deposit-data among dkg participants and returns all the partial
// signatures of the group according to public key of each DV.
func (e *exchanger) exchange(ctx context.Context, sigType sigType, set core.ParSignedDataSet) (map[core.PubKey][]core.ParSignedData, error) {
	// Start the process by storing current peer's ParSignedDataSet
	duty := core.NewSignatureDuty(uint64(sigType))

	err := e.sigdb.StoreInternal(ctx, duty, set)
	if err != nil {
		return nil, err
	}

	expectedSigs := len(set)

	for {
		select {
		case sigDatas, ok := <-e.sigDatasChan:
			if !ok {
				return nil, errors.New("sigdata channel has been closed")
			}

			if len(sigDatas) == expectedSigs {
				// We are done when we have ParSignedData of all the DVs from all each peer
				return sigDatas, nil
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// pushPsigs is responsible for writing partial signature data to sigChan obtained from other peers.
func (e *exchanger) pushPsigs(ctx context.Context, duty core.Duty, set map[core.PubKey][]core.ParSignedData) error {
	sigType := sigType(duty.Slot)

	if !e.dutyGaterFunc(duty) {
		return errors.New("unrecognized sigType", z.Int("sigType", int(sigType)))
	}

	e.sigData.lock.Lock()

	for pk, psigs := range set {
		_, ok := e.sigData.store[sigType]
		if !ok {
			e.sigData.store[sigType] = map[core.PubKey][]core.ParSignedData{}
		}

		e.sigData.store[sigType][pk] = psigs
	}

	data, ok := e.sigData.store[sigType]
	if !ok {
		e.sigData.lock.Unlock()
		return nil
	}

	ret := make(map[core.PubKey][]core.ParSignedData)
	maps.Copy(ret, data)

	e.sigData.lock.Unlock()

	select {
	case e.sigDatasChan <- ret:
	case <-ctx.Done():
		return errors.Wrap(ctx.Err(), "failed to feed collected sig data")
	}

	return nil
}

// noopDeadliner is a deadliner that does nothing.
type noopDeadliner struct{}

func (noopDeadliner) Add(core.Duty) bool {
	return true
}

func (noopDeadliner) C() <-chan core.Duty {
	return nil
}
