// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import "sync"

// prepState tracks per-beacon-node outcomes of the most recent SubmitProposalPreparations call.
// A BN whose most recent prep failed is excluded from subsequent Proposal calls so it cannot
// return a block with the wrong fee recipient. See issue #4477.
type prepState struct {
	mu       sync.RWMutex
	prepared map[string]bool
	seen     bool
}

func newPrepState() *prepState {
	return &prepState{prepared: make(map[string]bool)}
}

// markSuccess records a successful prep call for the given BN address.
func (p *prepState) markSuccess(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.prepared[addr] = true
	p.seen = true
}

// markFailure records a failed prep call for the given BN address.
func (p *prepState) markFailure(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.prepared[addr] = false
	p.seen = true
}

// preparedClients returns the subset of clients whose most recent prep succeeded.
// Before the first prep has run, or if no client is currently prepared, returns clients unchanged
// — failing closed here would cause missed proposals, which is worse than risking a mismatch
// (fee recipient mismatches are still rejected during proposal validation in multi.Proposal).
func (p *prepState) preparedClients(clients []Client) []Client {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.seen {
		return clients
	}

	var prepared []Client
	for _, c := range clients {
		if p.prepared[c.Address()] {
			prepared = append(prepared, c)
		}
	}

	if len(prepared) == 0 {
		return clients
	}

	return prepared
}
