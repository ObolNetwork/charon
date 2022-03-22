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

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/leadercast"
	"github.com/obolnetwork/charon/core/parsigex"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestSimnetNoNetwork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const n = 3
	manifest, p2pKeys, secretShares := app.NewClusterForT(t, 1, n, n, 99)

	var secrets []*bls_sig.SecretKey
	for _, share := range secretShares[0] {
		secret, err := tblsconv.ShareToSecret(share)
		require.NoError(t, err)
		secrets = append(secrets, secret)
	}

	parSigExFunc := parsigex.NewMemExFunc()
	lcastTransportFunc := leadercast.NewMemTransportFunc(ctx)

	var (
		eg      errgroup.Group
		results = make(chan simResult)
	)
	for i := 0; i < n; i++ {
		conf := app.Config{
			SimnetVMock:      true,
			MonitoringAddr:   testutil.AvailableAddr(t).String(), // Random monitoring address
			ValidatorAPIAddr: testutil.AvailableAddr(t).String(), // Random validatorapi address
			TestConfig: app.TestConfig{
				Manifest:           &manifest,
				P2PKey:             p2pKeys[i],
				DisablePing:        true,
				SimnetKeys:         []*bls_sig.SecretKey{secrets[i]},
				ParSigExFunc:       parSigExFunc,
				LcastTransportFunc: lcastTransportFunc,
				BroadcastCallback: func(ctx context.Context, duty core.Duty, key core.PubKey, data core.AggSignedData) error {
					results <- simResult{Duty: duty, Pubkey: key, Data: data}
					return nil
				},
				SimnetBMockOpts: []beaconmock.Option{
					beaconmock.WithSlotsPerEpoch(1),
					beaconmock.WithSlotDuration(time.Second),
				},
			},
			P2P: p2p.Config{},
		}

		eg.Go(func() error {
			return app.Run(ctx, conf)
		})
	}

	pubkey, err := tblsconv.KeyToCore(manifest.PublicKeys()[0])
	require.NoError(t, err)

	// Assert results
	go func() {
		var (
			remaining = 2
			counts    = make(map[core.Duty]int)
			datas     = make(map[core.Duty]core.AggSignedData)
		)
		for {
			res := <-results
			require.Equal(t, pubkey, res.Pubkey)

			// Assert the data and signature from all nodes are the same per duty.
			if counts[res.Duty] == 0 {
				datas[res.Duty] = res.Data
			} else {
				require.Equal(t, datas[res.Duty].Data, res.Data.Data)
				require.Equal(t, datas[res.Duty].Signature, res.Data.Signature)
			}

			// Assert we get results from all peers.
			counts[res.Duty]++
			if counts[res.Duty] == n {
				remaining--
			}
			if remaining != 0 {
				continue
			}

			cancel()

			return
		}
	}()

	require.NoError(t, eg.Wait())
}

type simResult struct {
	Duty   core.Duty
	Pubkey core.PubKey
	Data   core.AggSignedData
}
