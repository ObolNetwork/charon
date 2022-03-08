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
	"sync"
	"time"

	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

type sub func(context.Context, core.Duty, core.ParSignedDataSet) error

// NewMemExFunc returns a function that itself returns in-memory exchange components
// that exchange partial signatures.
func NewMemExFunc() func() core.ParSigEx {
	var (
		mu    sync.Mutex
		index int
		subs  = make(map[int][]sub)
	)

	return func() core.ParSigEx {
		mu.Lock()
		defer mu.Unlock()
		i := index
		index++

		return MemEx{
			addSub: func(s sub) {
				mu.Lock()
				defer mu.Unlock()

				subs[i] = append(subs[i], s)
			},

			getSubs: func() []sub {
				mu.Lock()
				defer mu.Unlock()

				var others []sub // Get other peer's subscriptions.
				for index, s := range subs {
					if index == i {
						continue
					}
					others = append(others, s...)
				}

				return others
			},
		}
	}
}

// MemEx provides an in-memory implementation of
// the core workflow's partial signature exchange component.
type MemEx struct {
	addSub  func(sub)
	getSubs func() []sub
}

// Broadcast broadcasts the partially signed duty data set to all peers.
func (s MemEx) Broadcast(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
	for _, sub := range s.getSubs() {
		err := sub(ctx, duty, set)
		if err != nil {
			return err
		}
	}

	return nil
}

// Subscribe registers a callback when a partially signed duty set
// is received from a peer.
func (s MemEx) Subscribe(fn func(context.Context, core.Duty, core.ParSignedDataSet) error) {
	s.addSub(fn)
}

const protocol = "/charon/parsigex/1.0.0"

func NewMemEx(tcpNode host.Host, index int, peers []peer.ID) *ParSigEx {
	memEx := &ParSigEx{
		mu:      sync.Mutex{},
		tcpNode: tcpNode,
		index:   index,
		peers:   peers,
	}
	memEx.tcpNode.SetStreamHandler(protocol, memEx.handle)

	return memEx
}

// MemEx provides an in-memory implementation of
// the core workflow's partial signature exchange component.
type ParSigEx struct {
	mu      sync.Mutex
	tcpNode host.Host
	index   int
	peers   []peer.ID
	ch      chan p2pMsg
	subs    []func(context.Context, core.Duty, core.ParSignedDataSet) error
}

func (m *ParSigEx) handle(s network.Stream) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var msg p2pMsg
	err := json.NewDecoder(s).Decode(&msg)
	if err != nil {
		log.Error(ctx, "decode parsigex message", err)
		return
	}

	select {
	case m.ch <- msg:
	case <-ctx.Done():
		log.Warn(ctx, "parsigex buffer full")
	}
}

// Broadcast broadcasts the partially signed duty data set to all peers.
func (m *ParSigEx) Broadcast(ctx context.Context, duty core.Duty, data core.ParSignedDataSet) error {
	b, err := json.Marshal(p2pMsg{
		Source: m.index,
		Duty:   duty,
		Data:   data,
	})
	if err != nil {
		return errors.Wrap(err, "marshal tcpNode msg")
	}

	var errs []error

	for i, p := range m.peers {
		if i == m.index {
			continue
		}

		err := sendData(ctx, m, p, b)
		if err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) == 0 {
		log.Debug(ctx, "parsigex broadcast duty success", z.Any("duty", duty))
	} else {
		log.Warn(ctx, "broadcast duty with errors", z.Int("success", len(m.peers)-len(errs)),
			z.Int("errors", len(errs)), z.Str("err_0", errs[0].Error()))
	}

	return nil
}

// Subscribe registers a callback when a partially signed duty set
// is received from a peer.
func (m *ParSigEx) Subscribe(fn func(context.Context, core.Duty, core.ParSignedDataSet) error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.subs = append(m.subs, fn)
}

func (m *ParSigEx) AwaitNext(ctx context.Context) (int, core.Duty, core.ParSignedDataSet, error) {
	select {
	case <-ctx.Done():
		return 0, core.Duty{}, nil, ctx.Err()
	case msg := <-m.ch:
		for _, sub := range m.subs {
			err := sub(ctx, msg.Duty, msg.Data)
			if err != nil {
				return 0, core.Duty{}, nil, err
			}
		}

		return msg.Source, msg.Duty, msg.Data, nil
	}
}

func sendData(ctx context.Context, m *ParSigEx, p peer.ID, b []byte) error {
	s, err := m.tcpNode.NewStream(ctx, p, protocol)
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
	Source int
	Duty   core.Duty
	Data   core.ParSignedDataSet
}
