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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/p2p"
)

func TestSimDuties(t *testing.T) {
	const n = 3
	ctx, cancel := context.WithCancel(context.Background())
	manifest, p2pKeys, _ := cluster.NewForT(t, n, n)
	records, err := manifest.ParsedENRs()
	require.NoError(t, err)

	var eg errgroup.Group

	for i := 0; i < n; i++ {
		conf := app.Config{
			MonitoringAddr:   availableAddr(t).String(), // Random monitoring address
			ValidatorAPIAddr: availableAddr(t).String(), // Random validatorapi address
			TestConfig: app.TestConfig{
				Manifest:        manifest,
				P2PKey:          p2pKeys[i],
				SimDutyPeriod:   time.Second,
				SimDutyCallback: nil,
			},
			P2P: p2p.Config{
				TCPAddrs: []string{tcpAddrFromENR(t, records[i])},
				UDPAddr:  udpAddrFromENR(t, records[i]),
			},
		}

		eg.Go(func() error {
			return app.Run(ctx, conf)
		})
	}

	time.Sleep(time.Second * 10)
	cancel()

	require.NoError(t, eg.Wait())
}
