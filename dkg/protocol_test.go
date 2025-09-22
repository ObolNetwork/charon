// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg_test

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cmd"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/relay"
)

func TestRunProtocol(t *testing.T) {
	const (
		numNodes = 4
	)

	clusterDir := t.TempDir()

	// Run "create cluster" command to setup cluster directory
	args := []string{
		"create", "cluster",
		"--cluster-dir", clusterDir,
		"--nodes", strconv.Itoa(numNodes),
		"--threshold", "3",
		"--num-validators", "3",
		"--network", eth2util.Holesky.Name,
		"--fee-recipient-addresses", "0x0000000000000000000000000000000000000000",
		"--withdrawal-addresses", "0x0000000000000000000000000000000000000000",
	}
	cmd := cmd.New()
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(t.Context())
	require.NoError(t, err)

	// Running the test protocol for all nodes
	eg := new(errgroup.Group)
	relayAddr := relay.StartRelay(t.Context(), t)

	stepsCounterCh := make(chan int, numNodes)

	for n := range numNodes {
		eg.Go(func() error {
			protocol := newTestProtocol()
			ndir := nodeDir(clusterDir, n)

			config := dkg.Config{
				DataDir:       ndir,
				ShutdownDelay: time.Second,
				P2P: p2p.Config{
					Relays:   []string{relayAddr},
					TCPAddrs: []string{testutil.AvailableAddr(t).String()},
				},
			}

			defer func() {
				stepsCounterCh <- protocol.stepCounter
			}()

			return dkg.RunProtocol(t.Context(), protocol, config)
		})
	}

	require.NoError(t, eg.Wait())

	for range numNodes {
		steps := <-stepsCounterCh
		require.Equal(t, 2, steps)
	}
}

type testProtocol struct {
	stepCounter int
}

var _ dkg.Protocol = (*testProtocol)(nil)

func newTestProtocol() *testProtocol {
	return &testProtocol{}
}

func (p *testProtocol) GetPeers(lock *cluster.Lock) ([]p2p.Peer, error) {
	return lock.Peers()
}

func (p *testProtocol) PostInit(context.Context, *dkg.ProtocolContext) error {
	return nil
}

func (p *testProtocol) Steps(*dkg.ProtocolContext) []dkg.ProtocolStep {
	return []dkg.ProtocolStep{
		&someStep{p: p},
		&someStep{p: p},
	}
}

type someStep struct {
	p *testProtocol
}

func (s *someStep) Run(ctx context.Context, pctx *dkg.ProtocolContext) error {
	s.p.stepCounter++

	return nil
}

func nodeDir(clusterDir string, i int) string {
	return fmt.Sprintf("%s/node%d", clusterDir, i)
}
