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

// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package parsigex

import (
	"context"
	"encoding/json"
	"time"

	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"go.opentelemetry.io/otel/trace"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

const protocol = "/charon/parsigex/1.0.0"

func NewParSigEx(tcpNode host.Host, peerIdx int, peers []peer.ID) *ParSigEx {
	parSigEx := &ParSigEx{
		tcpNode: tcpNode,
		peerIdx: peerIdx,
		peers:   peers,
	}
	parSigEx.tcpNode.SetStreamHandler(protocol, parSigEx.handle)

	return parSigEx
}

// ParSigEx exchanges partially signed duty data sets.
// It ensures that all partial signatures are persisted by all peers.
type ParSigEx struct {
	tcpNode host.Host
	peerIdx int
	peers   []peer.ID
	subs    []func(context.Context, core.Duty, core.ParSignedDataSet) error
}

func (m *ParSigEx) handle(s network.Stream) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	ctx = log.WithTopic(ctx, "parsigex")
	defer cancel()
	defer s.Close()

	var msg p2pMsg
	err := json.NewDecoder(s).Decode(&msg)
	if err != nil {
		log.Error(ctx, "decode parsigex message", err)
		return
	}

	var span trace.Span
	ctx, span = core.StartDutyTrace(ctx, msg.Duty, "core/parsigex.Handle")
	defer span.End()

	for _, sub := range m.subs {
		err := sub(ctx, msg.Duty, msg.Data)
		if err != nil {
			log.Error(ctx, "subscribe error", err)
		}
	}
}

// Broadcast broadcasts the partially signed duty data set to all peers.
func (m *ParSigEx) Broadcast(ctx context.Context, duty core.Duty, data core.ParSignedDataSet) error {
	b, err := json.Marshal(p2pMsg{
		Duty: duty,
		Data: data,
	})
	if err != nil {
		return errors.Wrap(err, "marshal tcpNode msg")
	}

	var errs []error

	for i, p := range m.peers {
		// Don't send to self
		if i == m.peerIdx {
			continue
		}

		err := sendData(ctx, m.tcpNode, p, b)
		if err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) == 0 {
		log.Debug(ctx, "parsigex broadcast duty success", z.Any("duty", duty))
	} else {
		// len(t.peers)-len(errs)-1 is total number of errors excluding broadcast to self case
		log.Warn(ctx, "broadcast duty with errors", z.Int("success", len(m.peers)-len(errs)-1),
			z.Int("errors", len(errs)), z.Str("err_0", errs[0].Error()))
	}

	return nil
}

// Subscribe registers a callback when a partially signed duty set
// is received from a peer. This is not thread safe, it must be called before starting to use parsigex.
func (m *ParSigEx) Subscribe(fn func(context.Context, core.Duty, core.ParSignedDataSet) error) {
	m.subs = append(m.subs, fn)
}

func sendData(ctx context.Context, tcpNode host.Host, p peer.ID, b []byte) error {
	s, err := tcpNode.NewStream(ctx, p, protocol)
	if err != nil {
		return errors.Wrap(err, "tcpNode stream")
	}

	_, err = s.Write(b)
	if err != nil {
		return errors.Wrap(err, "tcpNode write")
	}

	if err := s.Close(); err != nil {
		return errors.Wrap(err, "tcpNode close")
	}

	return nil
}

type p2pMsg struct {
	Duty core.Duty
	Data core.ParSignedDataSet
}
