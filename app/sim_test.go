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

package app_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/types"
)

// TestSimDuties starts a cluster of charon nodes and waits for each node to resolve identical duties.
// It relies on discv5 for peer discovery.
func TestSimDuties(t *testing.T) {
	const n = 3
	ctx, cancel := context.WithCancel(context.Background())
	manifest, p2pKeys, _ := types.NewClusterForT(t, 1, n, n, 0)

	asserter := &simDutyAsserter{
		asserter: asserter{
			Timeout: time.Second * 10,
		},
		N:     n,
		Slots: 2, // Assert 2 rounds/slots
	}

	var eg errgroup.Group

	for i := 0; i < n; i++ {
		conf := app.Config{
			MonitoringAddr:   availableAddr(t).String(), // Random monitoring address
			ValidatorAPIAddr: availableAddr(t).String(), // Random validatorapi address
			TestConfig: app.TestConfig{
				Manifest:        &manifest,
				P2PKey:          p2pKeys[i],
				SimDutyPeriod:   time.Millisecond * 10,
				SimDutyCallback: asserter.Callback(t),
			},
			P2P: p2p.Config{
				TCPAddrs: []string{tcpAddrFromENR(t, manifest.Peers[i].ENR)},
				UDPAddr:  udpAddrFromENR(t, manifest.Peers[i].ENR),
			},
		}

		eg.Go(func() error {
			return app.Run(ctx, conf)
		})
	}

	asserter.Await(t)
	cancel()

	require.NoError(t, eg.Wait())
}

// simDutyAsserter asserts that all nodes resolve identical duties.
type simDutyAsserter struct {
	asserter
	N     int
	Slots int

	mu     sync.Mutex
	duties map[types.Duty][][]byte
}

// Await waits for all nodes to ping each other or time out.
func (a *simDutyAsserter) Await(t *testing.T) {
	t.Helper()

	a.await(t, a.Slots)
}

// Callback returns the PingCallback function for the ith node.
func (a *simDutyAsserter) Callback(t *testing.T) func(duty types.Duty, data []byte) {
	t.Helper()

	return func(duty types.Duty, data []byte) {
		a.mu.Lock()
		defer a.mu.Unlock()

		datas := a.duties[duty]
		for _, prev := range datas {
			require.Equal(t, prev, data)
		}
		datas = append(datas, data)

		if len(datas) == a.N {
			t.Logf("All nodes resolved duty=%v", duty)
			a.callbacks.Store(duty, true)
		}

		if len(datas) == 1 {
			a.duties = make(map[types.Duty][][]byte)
		}
		a.duties[duty] = datas
	}
}
