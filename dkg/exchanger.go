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

	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/parsigdb"
	"github.com/obolnetwork/charon/core/parsigex"
	"github.com/obolnetwork/charon/p2p"
)

// Note: Following duty types shouldn't be confused with the duty types in core workflow. This was
// to get support from parsigex and parsigdb core components. This may subject to change when DKG
// package has its own networking and database components.
// Values of following constants should not change as it can break backwards compatibility.
const (
	// dutyLock is responsible for lock hash signed partial signatures exchange and aggregation.
	dutyLock core.DutyType = 101
	// dutyDepositData is responsible for deposit data signed partial signatures exchange and aggregation.
	dutyDepositData core.DutyType = 102
)

// sigData includes the fields obtained from sigdb when threshold is reached.
type sigData struct {
	duty   core.DutyType
	pubkey core.PubKey
	psigs  []core.ParSignedData
}

// exchanger is responsible for exchanging partial signatures between peers on libp2p.
type exchanger struct {
	sigChan chan sigData
	sigex   *parsigex.ParSigEx
	sigdb   *parsigdb.MemDB
	numVals int
}

func newExchanger(tcpNode host.Host, peerIdx int, peers []peer.ID, vals int) *exchanger {
	ex := &exchanger{
		// threshold is len(peers) to wait until we get all the partial sigs from all the peers per DV
		sigdb:   parsigdb.NewMemDB(len(peers)),
		sigex:   parsigex.NewParSigEx(tcpNode, new(p2p.Sender), peerIdx, peers),
		sigChan: make(chan sigData, len(peers)),
		numVals: vals,
	}

	// Wiring core workflow components
	ex.sigdb.SubscribeInternal(ex.sigex.Broadcast)
	ex.sigdb.SubscribeThreshold(ex.pushPsigs)
	ex.sigex.Subscribe(ex.sigdb.StoreExternal)

	return ex
}

// exchange exhanges partial signatures of lockhash/deposit-data among dkg participants and returns all the partial
// signatures of the group according to public key of each DV.
func (e *exchanger) exchange(ctx context.Context, duty core.DutyType, set core.ParSignedDataSet) (map[core.PubKey][]core.ParSignedData, error) {
	// Start the process by storing current peer's ParSignedDataSet
	err := e.sigdb.StoreInternal(ctx, core.Duty{Type: duty}, set)
	if err != nil {
		return nil, err
	}

	sets := make(map[core.PubKey][]core.ParSignedData)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case peerSet := <-e.sigChan:
			if duty != peerSet.duty {
				// Do nothing if duty doesn't match
				continue
			}
			sets[peerSet.pubkey] = peerSet.psigs
		}

		// We are done when we have ParSignedData of all the DVs from all each peer
		if len(sets) == e.numVals {
			break
		}
	}

	return sets, nil
}

// pushPsigs is responsible for writing partial signature data to sigChan obtained from other peers.
func (e *exchanger) pushPsigs(_ context.Context, duty core.Duty, pk core.PubKey, psigs []core.ParSignedData) error {
	e.sigChan <- sigData{
		duty:   duty.Type,
		pubkey: pk,
		psigs:  psigs,
	}

	return nil
}
