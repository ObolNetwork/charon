// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

// dataByPubkey holds the partial signatures collected per sigType and the pending exchange queries
// awaiting them. Both are guarded by lock.
type dataByPubkey struct {
	store   sigTypeStore
	queries []exchangeQuery
	lock    sync.Mutex
}

// exchangeQuery is a pending exchange call awaiting all its expected partial signatures for a sigType.
type exchangeQuery struct {
	sigType  sigType
	expected int
	// response is buffered (size 1) so resolveQueriesUnsafe never blocks, even when it runs on the
	// exchange goroutine itself (pushPsigs may resolve queries synchronously via StoreInternal).
	response chan<- map[core.PubKey][]core.ParSignedData
	cancel   <-chan struct{}
}

// exchanger is responsible for exchanging partial signatures between peers on libp2p.
type exchanger struct {
	sigex         *parsigex.ParSigEx
	sigdb         *parsigdb.MemDB
	sigTypes      map[sigType]bool
	sigData       dataByPubkey
	dutyGaterFunc func(duty core.Duty) bool
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
		sigdb:    parsigdb.NewMemDB(len(peers), noopDeadliner{}, parsigdb.NewMemDBMetadata(0, time.Now())), // metadata timestamps are used for metrics, irrelevant for DKG
		sigex:    parsigex.NewParSigEx(p2pNode, p2p.Send, peerIdx, peers, noopVerifier, dutyGaterFunc, p2p.WithSendTimeout(timeout), p2p.WithReceiveTimeout(timeout)),
		sigTypes: st,
		sigData: dataByPubkey{
			store: sigTypeStore{},
			lock:  sync.Mutex{},
		},
		dutyGaterFunc: dutyGaterFunc,
	}

	// Wiring core workflow components
	ex.sigdb.SubscribeInternal(ex.sigex.Broadcast)
	ex.sigdb.SubscribeThreshold(ex.pushPsigs)
	ex.sigex.Subscribe(ex.sigdb.StoreExternal)

	return ex
}

// exchange exchanges partial signatures of lockhash/deposit-data among dkg participants and returns all the partial
// signatures of the group according to public key of each DV.
func (e *exchanger) exchange(ctx context.Context, sigType sigType, set core.ParSignedDataSet) (map[core.PubKey][]core.ParSignedData, error) {
	// Start the process by storing current peer's ParSignedDataSet
	duty := core.NewSignatureDuty(uint64(sigType))

	err := e.sigdb.StoreInternal(ctx, duty, set)
	if err != nil {
		return nil, err
	}

	cancel := make(chan struct{})
	defer close(cancel)

	response := make(chan map[core.PubKey][]core.ParSignedData, 1)

	// Register the query, then resolve immediately in case all expected signatures are already
	// collected (e.g. peers delivered theirs before the StoreInternal above completed the threshold).
	e.sigData.lock.Lock()
	e.sigData.queries = append(e.sigData.queries, exchangeQuery{
		sigType:  sigType,
		expected: len(set),
		response: response,
		cancel:   cancel,
	})
	e.resolveQueriesUnsafe()
	e.sigData.lock.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case data := <-response:
		return data, nil
	}
}

// resolveQueriesUnsafe delivers the collected signatures to every pending query whose sigType has
// reached its expected count, dropping cancelled queries. It must be called with sigData.lock held.
func (e *exchanger) resolveQueriesUnsafe() {
	var remaining []exchangeQuery

	for _, q := range e.sigData.queries {
		if cancelled(q.cancel) {
			continue
		}

		data := e.sigData.store[q.sigType]
		if len(data) != q.expected {
			remaining = append(remaining, q)
			continue
		}

		// We are done when we have ParSignedData of all the DVs from each peer.
		ret := make(map[core.PubKey][]core.ParSignedData, len(data))
		maps.Copy(ret, data)

		q.response <- ret // Never blocks: response is buffered and each query is resolved at most once.
	}

	e.sigData.queries = remaining
}

// cancelled returns true if the channel is closed.
func cancelled(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// pushPsigs stores partial signature data obtained from peers and resolves any pending query in
// exchange whose expected signatures are now all collected.
func (e *exchanger) pushPsigs(_ context.Context, duty core.Duty, set map[core.PubKey][]core.ParSignedData) error {
	sigType := sigType(duty.Slot)

	if !e.dutyGaterFunc(duty) {
		return errors.New("unrecognized sigType", z.Int("sigType", int(sigType)))
	}

	e.sigData.lock.Lock()
	defer e.sigData.lock.Unlock()

	_, ok := e.sigData.store[sigType]
	if !ok {
		e.sigData.store[sigType] = map[core.PubKey][]core.ParSignedData{}
	}

	maps.Copy(e.sigData.store[sigType], set)

	e.resolveQueriesUnsafe()

	return nil
}

// noopDeadliner is a deadliner that does nothing.
type noopDeadliner struct{}

func (noopDeadliner) Add(core.Duty) core.DeadlineStatus {
	return core.DeadlineScheduled
}

func (noopDeadliner) C() <-chan core.Duty {
	return nil
}
