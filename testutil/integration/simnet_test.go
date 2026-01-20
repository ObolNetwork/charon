// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package integration_test

import (
	"context"
	"math/rand"
	"sync"
	"testing"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/parsigex"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
	"github.com/obolnetwork/charon/testutil/relay"
)

// vcType enumerates the different types of VCs.
type vcType int

const (
	vcUnknown vcType = 0
	vcVmock   vcType = 1
)

//go:generate go test . -integration -v -run=TestSimnetDuties

func TestSimnetDuties(t *testing.T) {
	// skipIfDisabled(t)

	tests := []struct {
		name               string
		scheduledType      core.DutyType
		duties             []core.DutyType
		builderAPI         bool
		pregenRegistration bool
		exit               bool
		vcType             vcType
	}{
		{
			name:          "attester with mock VCs",
			scheduledType: core.DutyAttester,
			duties:        []core.DutyType{core.DutyPrepareAggregator, core.DutyAttester, core.DutyAggregator},
			vcType:        vcVmock,
		},
		{
			name:          "proposer with mock VCs",
			scheduledType: core.DutyProposer,
			duties:        []core.DutyType{core.DutyProposer, core.DutyRandao},
			vcType:        vcVmock,
		},
		{
			name:          "sync committee with mock VCs",
			scheduledType: core.DutySyncMessage,
			duties:        []core.DutyType{core.DutyPrepareSyncContribution, core.DutySyncMessage, core.DutySyncContribution},
			vcType:        vcVmock,
		},
		// TODO(andrei): Need a redesign due to how builder registration is handled now.
		// {
		// 	name:       "builder registration with mock VCs",
		// 	duties:     []core.DutyType{core.DutyBuilderRegistration},
		// 	builderAPI: true,
		// 	vcType:     vcVmock,
		// },
		// {
		// 	name:               "pre-generate registrations",
		// 	duties:             []core.DutyType{core.DutyBuilderRegistration},
		// 	builderAPI:         true,
		// 	pregenRegistration: true,
		// },
		// {
		// 	name:          "proposer with mock VCs with builder API",
		// 	scheduledType: core.DutyProposer,
		// 	duties:        []core.DutyType{core.DutyBuilderRegistration, core.DutyProposer, core.DutyRandao},
		// 	vcType:        vcVmock,
		// 	builderAPI:    true,
		// },
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Logf("Running test: %v", t.Name())

			args := newSimnetArgs(t)
			args.BuilderAPI = test.builderAPI
			args.VoluntaryExit = test.exit

			switch test.vcType {
			case vcVmock:
				args.VMocks = true
			case vcUnknown:
			}

			if test.scheduledType != core.DutyAttester {
				// Beaconmock enables attester duties by default.
				args.BMockOpts = append(args.BMockOpts, beaconmock.WithNoAttesterDuties())
			}

			if test.scheduledType != core.DutyProposer {
				// Beaconmock enables proposer duties by default.
				args.BMockOpts = append(args.BMockOpts, beaconmock.WithNoProposerDuties())
			} else {
				// Use synthetic duties instead of deterministic beaconmock duties.
				args.SyntheticProposals = true
			}

			if test.scheduledType != core.DutySyncMessage {
				// Beaconmock enables sync committee duties by default.
				args.BMockOpts = append(args.BMockOpts, beaconmock.WithNoSyncCommitteeDuties())
			} else {
				// Enable for all epochs
				args.BMockOpts = append(args.BMockOpts, beaconmock.WithDeterministicSyncCommDuties(2, 2))
			}

			expect := newSimnetExpect(args.N, test.duties...)
			testSimnet(t, args, expect)
		})
	}
}

type simnetArgs struct {
	N                  int
	VMocks             bool
	VAPIAddrs          []string
	P2PKeys            []*k1.PrivateKey
	SimnetKeys         []tbls.PrivateKey
	BMockOpts          []beaconmock.Option
	Lock               cluster.Lock
	ErrChan            chan error
	BuilderAPI         bool
	SyntheticProposals bool
	VoluntaryExit      bool
}

// newSimnetArgs defines the default simnet test args.
func newSimnetArgs(t *testing.T) simnetArgs {
	t.Helper()

	const (
		n      = 3
		numDVs = 1
	)

	seed := 99
	random := rand.New(rand.NewSource(int64(seed)))
	lock, p2pKeys, secretShares := cluster.NewForT(t, numDVs, n, n, seed, random, func(definition *cluster.Definition) {
		definition.ForkVersion = []byte{0x01, 0x01, 0x70, 0x00}
	})

	secrets := secretShares[0]

	var vapiAddrs []string
	for range n {
		vapiAddrs = append(vapiAddrs, testutil.AvailableAddr(t).String())
	}

	return simnetArgs{
		N:          n,
		VAPIAddrs:  vapiAddrs,
		P2PKeys:    p2pKeys,
		SimnetKeys: secrets,
		Lock:       lock,
		ErrChan:    make(chan error, 1),
	}
}

// simnetExpect defines which duties (including how many of each) are expected in simnet tests.
type simnetExpect struct {
	mu      sync.Mutex
	actuals map[core.DutyType][]bool
	Errs    chan error
}

// Assert tests whether the duty is expected for this peer and also updates internal counters.
func (e *simnetExpect) Assert(t *testing.T, typ core.DutyType, peerIdx int) {
	t.Helper()

	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.actuals[typ]; !ok {
		t.Logf("unexpected duty, type=%v", typ)

		e.Errs <- errors.New("unexpected duty type", z.Any("type", typ))
	}

	e.actuals[typ][peerIdx] = true
	t.Logf("asserted duty, type=%v, remaining=%d", typ, remaining(e.actuals[typ]))
}

// Done returns true if all duties have been asserted sufficient number of times.
func (e *simnetExpect) Done(t *testing.T) bool {
	t.Helper()

	e.mu.Lock()
	defer e.mu.Unlock()

	for k, v := range e.actuals {
		if remaining(v) > 0 {
			t.Logf("assertion not done yet, duty type=%v, remaining=%d", k, remaining(v))
			return false
		}
	}

	t.Logf("assertion done, no duties remaining")

	return true
}

// remaining returns the number of falses in slice.
func remaining(actuals []bool) int {
	var remaining int

	for _, actual := range actuals {
		if !actual {
			remaining++
		}
	}

	return remaining
}

// newSimnetExpect returns a new simnetExpect with all duties of equal count.
func newSimnetExpect(peers int, duties ...core.DutyType) *simnetExpect {
	actuals := make(map[core.DutyType][]bool)
	for _, duty := range duties {
		actuals[duty] = make([]bool, peers)
	}

	return &simnetExpect{
		actuals: actuals,
		Errs:    make(chan error, 1),
	}
}

// testSimnet spins up a simnet cluster of N charon nodes connected via in-memory transports.
// It asserts successful end-2-end attestation broadcast from all nodes for 2 slots.
func testSimnet(t *testing.T, args simnetArgs, expect *simnetExpect) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	relayAddr := relay.StartRelay(ctx, t)
	parSigExFunc := parsigex.NewMemExFunc(args.N)

	type simResult struct {
		PeerIdx int
		Duty    core.Duty
		Pubkey  core.PubKey
		Data    core.SignedData
	}

	var (
		eg      errgroup.Group
		results = make(chan simResult)
	)

	for i := range args.N {
		peerIdx := i
		conf := app.Config{
			Log:              log.DefaultConfig(),
			Feature:          featureset.DefaultConfig(),
			SimnetBMock:      true,
			SimnetVMock:      args.VMocks,
			MonitoringAddr:   testutil.AvailableAddr(t).String(), // Random monitoring address
			ValidatorAPIAddr: args.VAPIAddrs[i],
			TestConfig: app.TestConfig{
				Lock:   &args.Lock,
				P2PKey: args.P2PKeys[i],
				TestPingConfig: p2p.TestPingConfig{
					MaxBackoff: time.Second,
				},
				SimnetKeys:   []tbls.PrivateKey{args.SimnetKeys[i]},
				ParSigExFunc: parSigExFunc,
				BroadcastCallback: func(_ context.Context, duty core.Duty, set core.SignedDataSet) error {
					for key, data := range set {
						select {
						case <-ctx.Done():
							return ctx.Err()
						case results <- simResult{Duty: duty, Pubkey: key, Data: data, PeerIdx: peerIdx}:
						}
					}

					return nil
				},
				SimnetBMockOpts: append([]beaconmock.Option{
					beaconmock.WithSlotsPerEpoch(1),
				}, args.BMockOpts...),
			},
			P2P: p2p.Config{
				TCPAddrs: []string{testutil.AvailableAddr(t).String()},
				Relays:   []string{relayAddr},
			},
			BuilderAPI:              args.BuilderAPI,
			SyntheticBlockProposals: args.SyntheticProposals,
		}

		eg.Go(func() error {
			defer cancel()
			return app.Run(ctx, conf)
		})
	}

	// Assert results
	type routineResult struct {
		expect          []byte
		actual          []byte
		expectSig       core.Signature
		actualSig       core.Signature
		expectPublicKey string
		actualPublicKey core.PubKey
	}

	errCh := make(chan error)
	routineResCh := make(chan routineResult)

	go func() {
		datas := make(map[core.Duty]core.SignedData)

		defer func() {
			close(routineResCh)
			close(errCh)
		}()

		for {
			var res simResult
			select {
			case <-ctx.Done():
				return
			case res = <-results:
			}

			// Assert the data and signature from all nodes are the same per duty.
			if _, ok := datas[res.Duty]; !ok {
				datas[res.Duty] = res.Data
			} else {
				expect, err := datas[res.Duty].MarshalJSON()
				errCh <- err

				actual, err := res.Data.MarshalJSON()
				errCh <- err

				routineRes := routineResult{
					expect:          expect,
					actual:          actual,
					expectSig:       datas[res.Duty].Signature(),
					actualSig:       res.Data.Signature(),
					expectPublicKey: args.Lock.Validators[0].PublicKeyHex(),
					actualPublicKey: res.Pubkey,
				}
				routineResCh <- routineRes
			}

			// Assert we get results for all types from all peers.
			expect.Assert(t, res.Duty.Type, res.PeerIdx)

			if expect.Done(t) {
				cancel()
				return
			}
		}
	}()

	finishLoop := true
	for finishLoop {
		select {
		case err := <-errCh:
			require.NoError(t, err)
		case res := <-routineResCh:
			require.Equal(t, res.expect, res.actual)
			require.Equal(t, res.expectSig, res.actualSig)
			require.EqualValues(t, res.expectPublicKey, res.actualPublicKey)
		case <-ctx.Done():
			finishLoop = false
		}
	}

	// Wire err channel (for docker errors)
	eg.Go(func() error {
		select {
		case <-ctx.Done():
			return nil
		case err := <-args.ErrChan:
			cancel()
			return err
		case err := <-expect.Errs:
			cancel()
			return err
		}
	})

	err := eg.Wait()
	testutil.SkipIfBindErr(t, err)
	testutil.RequireNoError(t, err)
}
