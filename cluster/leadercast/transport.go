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

package leadercast

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
	"github.com/obolnetwork/charon/types"
)

const protocol = "/charon/leadercast/1.0.0"

// Transport abstracts the transport layer for leader cast consensus.
type Transport interface {
	Broadcast(ctx context.Context, source int, d types.Duty, data []byte) error
	AwaitNext(ctx context.Context) (source int, d types.Duty, data []byte, err error)
}

func NewP2PTransport(tcpNode host.Host, index int, peers []peer.ID) Transport {
	t := &p2pTransport{
		tcpNode: tcpNode,
		peers:   peers,
		index:   index,
		ch:      make(chan p2pMsg),
	}
	t.tcpNode.SetStreamHandler(protocol, t.handle)

	return t
}

type p2pTransport struct {
	tcpNode host.Host
	index   int
	peers   []peer.ID
	ch      chan p2pMsg
}

func (t *p2pTransport) handle(s network.Stream) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var msg p2pMsg
	err := json.NewDecoder(s).Decode(&msg)
	if err != nil {
		log.Error(ctx, "decode leadercast message", err)
		return
	}
	select {
	case t.ch <- msg:
	case <-ctx.Done():
		log.Warn(ctx, "leadercast transport buffer full")
	}
}

func (t *p2pTransport) Broadcast(ctx context.Context, source int, d types.Duty, data []byte) error {
	b, err := json.Marshal(p2pMsg{
		Source: source,
		Duty:   d,
		Data:   data,
	})
	if err != nil {
		return errors.Wrap(err, "marshal tcpNode msg")
	}

	var errs []error

	for i, p := range t.peers {
		if i == t.index {
			// Don't send to self.
			continue
		}

		err := sendData(ctx, t, p, b)
		if err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) == 0 {
		log.Debug(ctx, "leader broadcast duty success", z.Any("duty", d))
	} else {
		log.Warn(ctx, "broadcast duty with errors", z.Int("success", len(t.peers)-len(errs)),
			z.Int("errors", len(errs)), z.Str("err_0", errs[0].Error()))
	}

	return nil
}

func (t *p2pTransport) AwaitNext(ctx context.Context) (int, types.Duty, []byte, error) {
	var msg p2pMsg

	err := async(ctx, func() error {
		msg = <-t.ch
		return nil
	})

	return msg.Source, msg.Duty, msg.Data, err
}

func sendData(ctx context.Context, t *p2pTransport, p peer.ID, b []byte) error {
	s, err := t.tcpNode.NewStream(ctx, p, protocol)
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
	Duty   types.Duty
	Data   []byte
}
