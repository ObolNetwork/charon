// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
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
	// sigDepositData is responsible for deposit data signed partial signatures exchange and aggregation.
	sigDepositData sigType = 102
	// sigValidatorRegistration is responsible for the pre-generated validator registration exchange and aggregation.
	sigValidatorRegistration sigType = 103
)

// sigTypeStore is a shorthand for a map of sigType to map of core.PubKey to slice of core.ParSignedData.
type sigTypeStore map[sigType]map[core.PubKey][]core.ParSignedData

// dataByPubkey maps a sigType to its map of public key to slice of core.ParSignedData..
type dataByPubkey struct {
	numVals int
	store   sigTypeStore
	lock    sync.Mutex
}

// set sets data for the given sigType and core.PubKey.
func (stb *dataByPubkey) set(pubKey core.PubKey, sigType sigType, data []core.ParSignedData) {
	stb.lock.Lock()
	defer stb.lock.Unlock()

	_, ok := stb.store[sigType]
	if !ok {
		stb.store[sigType] = map[core.PubKey][]core.ParSignedData{}
	}

	stb.store[sigType][pubKey] = data
}

// get gets all the core.ParSignedData for a given core.PubKey.
func (stb *dataByPubkey) get(sigType sigType) (map[core.PubKey][]core.ParSignedData, bool) {
	stb.lock.Lock()
	defer stb.lock.Unlock()

	data, ok := stb.store[sigType]
	if !ok {
		return nil, ok
	}

	if len(data) != stb.numVals {
		return nil, false
	}

	ret := make(map[core.PubKey][]core.ParSignedData)

	for k, v := range data {
		ret[k] = v
	}

	return ret, ok
}

// exchanger is responsible for exchanging partial signatures between peers on libp2p.
type exchanger struct {
	sigex    *parsigex.ParSigEx
	sigdb    *parsigdb.MemDB
	sigTypes map[sigType]bool
	sigData  dataByPubkey
}

func newExchanger(tcpNode host.Host, peerIdx int, peers []peer.ID, vals int, sigTypes []sigType) *exchanger {
	// Partial signature roots not known yet, so skip verification in parsigex, rather verify before we aggregate.
	noopVerifier := func(ctx context.Context, duty core.Duty, key core.PubKey, data core.ParSignedData) error {
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

		return st[sigType(duty.Slot)]
	}

	ex := &exchanger{
		// threshold is len(peers) to wait until we get all the partial sigs from all the peers per DV
		sigdb:    parsigdb.NewMemDB(len(peers), noopDeadliner{}),
		sigex:    parsigex.NewParSigEx(tcpNode, p2p.Send, peerIdx, peers, noopVerifier, dutyGaterFunc),
		sigTypes: st,
		sigData: dataByPubkey{
			store:   sigTypeStore{},
			numVals: vals,
			lock:    sync.Mutex{},
		},
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

	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-tick.C:
			// We are done when we have ParSignedData of all the DVs from all each peer
			if data, ok := e.sigData.get(sigType); ok {
				return data, nil
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// pushPsigs is responsible for writing partial signature data to sigChan obtained from other peers.
func (e *exchanger) pushPsigs(_ context.Context, duty core.Duty, set map[core.PubKey][]core.ParSignedData) error {
	sigType := sigType(duty.Slot)

	if !e.sigTypes[sigType] {
		return errors.New("unrecognized sigType", z.Int("sigType", int(sigType)))
	}

	for pk, psigs := range set {
		e.sigData.set(pk, sigType, psigs)
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
