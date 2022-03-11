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

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

const protocol = "/charon/parsigex/1.0.0"

func NewParSigEx(tcpNode host.Host, sourceID peer.ID, peers []peer.ID) *ParSigEx {
	parSigEx := &ParSigEx{
		tcpNode: tcpNode,
		peerIdx: sourceID,
		peers:   peers,
	}
	parSigEx.tcpNode.SetStreamHandler(protocol, parSigEx.handle)

	return parSigEx
}

// ParSigEx exchanges partially signed duty data sets.
// It ensures that all partial signatures are persisted by all peers.
type ParSigEx struct {
	tcpNode host.Host
	peerIdx peer.ID
	peers   []peer.ID
	subs    []func(context.Context, core.Duty, core.ParSignedDataSet) error
}

func (m *ParSigEx) handle(s network.Stream) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	defer s.Close()

	var msg p2pMsg
	err := json.NewDecoder(s).Decode(&msg)
	if err != nil {
		log.Error(ctx, "decode parsigex message", err)
		return
	}

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

	for _, p := range m.peers {
		// Don't send to self
		if p == m.peerIdx {
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
