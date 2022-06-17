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
//nolint:wrapcheck,errcheck
package sync

import (
	"bytes"
	"context"
	"io"
	"time"

	pool "github.com/libp2p/go-buffer-pool"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
)

const PingSize = 32

type ServerPing struct {
	Host host.Host
}

func NewPingServer(ctx context.Context, h host.Host, msg []byte) *ServerPing {
	ps := &ServerPing{h}
	h.SetStreamHandler(ID, func(s network.Stream) {
		buf := pool.Get(PingSize)
		defer pool.Put(buf)

		errCh := make(chan error, 1)
		defer close(errCh)
		for {
			_, err := io.ReadFull(s, buf)
			if err != nil {
				errCh <- err
				return
			}

			if !bytes.Equal(msg, buf) {
				log.Debug(ctx, "Messages are not equal!!")
			}

			_, err = s.Write(buf)
			if err != nil {
				errCh <- err
				return
			}
		}
	})

	return ps
}

// Result is a result of a ping attempt, either an RTT or an error.
type Result struct {
	RTT   time.Duration
	Error error
}

func pingError(err error) chan Result {
	ch := make(chan Result, 1)
	ch <- Result{Error: err}
	close(ch)

	return ch
}

func ClientPing(ctx context.Context, h host.Host, p peer.ID, msg []byte) <-chan Result {
	s, err := h.NewStream(network.WithUseTransient(ctx, "ping"), p, ID)
	if err != nil {
		return pingError(err)
	}

	ctx, cancel := context.WithCancel(ctx)

	out := make(chan Result)
	go func() {
		defer close(out)
		defer cancel()

		for ctx.Err() == nil {
			var res Result
			res.RTT, res.Error = ping(s, msg)

			// canceled, ignore everything.
			if ctx.Err() != nil {
				return
			}

			// No error, record the RTT.
			if res.Error == nil {
				h.Peerstore().RecordLatency(p, res.RTT)
			}

			select {
			case out <- res:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		// forces the ping to abort.
		<-ctx.Done()
		s.Reset()
	}()

	return out
}

func ping(s network.Stream, msg []byte) (time.Duration, error) {
	before := time.Now()
	_, err := s.Write(msg)
	if err != nil {
		return 0, err
	}

	rbuf := pool.Get(PingSize)
	defer pool.Put(rbuf)

	_, err = io.ReadFull(s, rbuf)
	if err != nil {
		return 0, err
	}

	if !bytes.Equal(msg, rbuf) {
		return 0, errors.New("messages not equal")
	}

	return time.Since(before), nil
}
