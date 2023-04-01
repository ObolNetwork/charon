// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package integration_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/priority"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestInfoSync(t *testing.T) {
	skipIfDisabled(t)

	featureset.EnableForT(t, featureset.Priority)

	ctx, cancel := context.WithCancel(context.Background())

	const n = 3
	lock, p2pKeys, _ := cluster.NewForT(t, 1, n, n, 0)

	asserter := &priorityAsserter{
		asserter: asserter{Timeout: time.Second * 10},
		N:        n,
	}

	var tcpNodesLock sync.Mutex
	var tcpNodes []host.Host

	// Hard code peer addresses and protocols
	tcpNodeCallback := func(tcpNode host.Host) {
		tcpNodesLock.Lock()
		defer tcpNodesLock.Unlock()

		for _, other := range tcpNodes {
			other.Peerstore().AddAddrs(tcpNode.ID(), tcpNode.Addrs(), peerstore.PermanentAddrTTL)
			err := other.Peerstore().AddProtocols(tcpNode.ID(), priority.Protocols()...)
			require.NoError(t, err)

			tcpNode.Peerstore().AddAddrs(other.ID(), other.Addrs(), peerstore.PermanentAddrTTL)
			err = tcpNode.Peerstore().AddProtocols(other.ID(), priority.Protocols()...)
			require.NoError(t, err)
		}
		tcpNodes = append(tcpNodes, tcpNode)
	}

	var eg errgroup.Group
	for i := 0; i < n; i++ {
		i := i // Copy iteration variable
		conf := app.Config{
			Log:              log.DefaultConfig(),
			Feature:          featureset.DefaultConfig(),
			SimnetBMock:      true,
			MonitoringAddr:   testutil.AvailableAddr(t).String(), // Random monitoring address
			ValidatorAPIAddr: testutil.AvailableAddr(t).String(), // Random validatorapi address
			TestConfig: app.TestConfig{
				PrioritiseCallback: asserter.Callback(t, i),
				Lock:               &lock,
				P2PKey:             p2pKeys[i],
				TCPNodeCallback:    tcpNodeCallback,
				SimnetBMockOpts: []beaconmock.Option{
					beaconmock.WithNoAttesterDuties(),
					beaconmock.WithNoProposerDuties(),
					beaconmock.WithNoSyncCommitteeDuties(),
					beaconmock.WithSlotsPerEpoch(1),
				},
			},
			P2P: p2p.Config{
				TCPAddrs: []string{testutil.AvailableAddr(t).String()},
			},
		}

		eg.Go(func() error {
			defer cancel()
			return app.Run(ctx, conf)
		})
	}

	eg.Go(func() error {
		defer cancel()
		return asserter.Await(ctx, t)
	})

	err := eg.Wait()
	testutil.SkipIfBindErr(t, err)
	require.NoError(t, err)
}

// priorityAsserter asserts that all nodes resolved the same priorities.
type priorityAsserter struct {
	asserter
	N int
}

// Await waits for all nodes to ping each other or time out.
func (a *priorityAsserter) Await(ctx context.Context, t *testing.T) error {
	t.Helper()
	return a.await(ctx, t, a.N)
}

// Callback returns the PingCallback function for the ith node.
func (a *priorityAsserter) Callback(t *testing.T, i int) func(ctx context.Context, duty core.Duty, results []priority.TopicResult) error {
	t.Helper()

	return func(ctx context.Context, duty core.Duty, results []priority.TopicResult) error {
		expect := map[string]string{
			"version":  fmt.Sprint(version.Supported()),
			"protocol": fmt.Sprint(app.Protocols()),
			"proposal": fmt.Sprint(app.ProposalTypes(false, false)),
		}

		if !assert.Len(t, results, len(expect)) {
			return errors.New("unexpected number of results")
		}

		for _, result := range results {
			if len(result.Priorities) == 0 {
				// Some but not all peers participated, ignore this result.
				return nil
			}

			if !assert.Equal(t, expect[result.Topic], fmt.Sprint(result.PrioritiesOnly())) {
				return errors.New("unexpected priorities")
			}
		}

		a.callbacks.Store(fmt.Sprint(i), true)

		return nil
	}
}
