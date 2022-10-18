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

package beaconmock

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/gorilla/mux"
	"github.com/r3labs/sse/v2"

	"github.com/obolnetwork/charon/testutil"
)

const streamID = "block_events"

func NewBlockProducer() *BlockProducer {
	server := sse.New()
	server.CreateStream(streamID)

	return &BlockProducer{server: server}
}

// BlockProducer is a stateful struct for providing deterministic block roots based on slot events.
type BlockProducer struct {
	// Immutable state
	server *sse.Server

	// Mutable state
	mu          sync.Mutex
	event       eth2v1.HeadEvent
	currentHead eth2p0.Slot
}

// UpdateHead updates current head based on provided slot.
func (b *BlockProducer) UpdateHead(slot eth2p0.Slot) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.currentHead = slot
	b.event = testutil.RandomHeadEvent(slot)
	b.publishEvents()
}

// handleGetBlockRoot is an  http handler to handle "/eth/v1/beacon/blocks/{block_id}/root" endpoint.
func (b *BlockProducer) handleGetBlockRoot(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()

	params := mux.Vars(r)
	if params["block_id"] != "head" && params["block_id"] != strconv.Itoa(int(b.currentHead)) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"code": 400, "message": "Invalid block ID: %s"}`, params["block_id"])))

		return
	}

	hexRoot := "0x" + hex.EncodeToString(b.event.Block[:])
	_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"root":"%s"}}`, hexRoot)))
}

// publishEvents published events to the given stream.
func (b *BlockProducer) publishEvents() {
	b.server.Publish(streamID, &sse.Event{
		Event: []byte("head"),
		Data:  []byte(b.event.String()),
	})
}

// serveEvents is a http handler to handle "/eth/v1/events".
func (b *BlockProducer) serveEvents(w http.ResponseWriter, r *http.Request) {
	topic := r.URL.Query().Get("topics")
	if topic != "head" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"code": 400, "message": "Invalid topic: %s"}`, topic)))

		return
	}

	// Add stream id for server to serve events on.
	r.URL.RawQuery = r.URL.RawQuery + "&stream=" + streamID

	b.server.ServeHTTP(w, r)
}
