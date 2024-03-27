// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package integration_test

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
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
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

// vcType enumerates the different types of VCs.
type vcType int

const (
	vcUnknown vcType = 0
	vcVmock   vcType = 1
	vcTeku    vcType = 2
)

//go:generate go test . -integration -v -run=TestSimnetDuties

func TestSimnetDuties(t *testing.T) {
	skipIfDisabled(t)

	tests := []struct {
		name               string
		scheduledType      core.DutyType
		duties             []core.DutyType
		builderAPI         bool
		tekuRegistration   bool
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
			name:          "attester with teku",
			scheduledType: core.DutyAttester,
			duties:        []core.DutyType{core.DutyAttester}, // Teku does not support beacon committee selection
			vcType:        vcTeku,
		},
		{
			name:          "proposer with mock VCs",
			scheduledType: core.DutyProposer,
			duties:        []core.DutyType{core.DutyProposer, core.DutyRandao},
			vcType:        vcVmock,
		},
		{
			name:          "proposer with teku",
			scheduledType: core.DutyProposer,
			duties:        []core.DutyType{core.DutyProposer, core.DutyRandao},
			vcType:        vcTeku,
		},
		{
			name:       "builder registration with mock VCs",
			duties:     []core.DutyType{core.DutyBuilderRegistration},
			builderAPI: true,
			vcType:     vcVmock,
		},
		{
			name:             "builder registration with teku",
			duties:           []core.DutyType{core.DutyBuilderRegistration},
			tekuRegistration: true,
			builderAPI:       true,
			vcType:           vcTeku,
		},
		{
			name:          "sync committee with mock VCs",
			scheduledType: core.DutySyncMessage,
			duties:        []core.DutyType{core.DutyPrepareSyncContribution, core.DutySyncMessage, core.DutySyncContribution},
			vcType:        vcVmock,
		},
		{
			name:          "sync committee with teku",
			scheduledType: core.DutySyncMessage,
			duties:        []core.DutyType{core.DutySyncMessage}, // Teku doesn't support sync committee selection.
			vcType:        vcTeku,
		},
		{
			name:   "voluntary exit with teku",
			duties: []core.DutyType{core.DutyExit},
			exit:   true,
			vcType: vcTeku,
		},
		{
			name:               "pre-generate registrations",
			duties:             []core.DutyType{core.DutyBuilderRegistration},
			builderAPI:         true,
			pregenRegistration: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Logf("Running test: %v", t.Name())

			args := newSimnetArgs(t)
			args.TekuRegistration = test.tekuRegistration
			args.BuilderAPI = test.builderAPI
			args.VoluntaryExit = test.exit

			if test.vcType == vcTeku {
				// TODO: investigate why teku does not query bn.
				t.SkipNow()

				return
			}

			if test.vcType == vcTeku {
				for i := 0; i < args.N; i++ {
					args = startTeku(t, args, i)
				}
			} else if test.vcType == vcVmock {
				args.VMocks = true
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
	TekuRegistration   bool
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
	lock, p2pKeys, secretShares := cluster.NewForT(t, numDVs, n, n, seed, random)

	secrets := secretShares[0]

	var vapiAddrs []string
	for i := 0; i < n; i++ {
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

	relayAddr := startRelay(ctx, t)
	// NOTE: We can add support for in-memory transport to QBFT.
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
	for i := 0; i < args.N; i++ {
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
	go func() {
		datas := make(map[core.Duty]core.SignedData)
		for {
			var res simResult
			select {
			case <-ctx.Done():
				return
			case res = <-results:
			}

			require.EqualValues(t, args.Lock.Validators[0].PublicKeyHex(), res.Pubkey)

			// Assert the data and signature from all nodes are the same per duty.
			if _, ok := datas[res.Duty]; !ok {
				datas[res.Duty] = res.Data
			} else {
				expect, err := datas[res.Duty].MarshalJSON()
				require.NoError(t, err)
				actual, err := res.Data.MarshalJSON()
				require.NoError(t, err)
				require.Equal(t, expect, actual)
				require.Equal(t, datas[res.Duty].Signature(), res.Data.Signature())
			}

			// Assert we get results for all types from all peers.
			expect.Assert(t, res.Duty.Type, res.PeerIdx)

			if expect.Done(t) {
				cancel()
				return
			}
		}
	}()

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

type tekuCmd []string

var (
	tekuVC tekuCmd = []string{
		"validator-client",
		"--network=auto",
		"--log-destination=console",
		"--validators-proposer-default-fee-recipient=0x000000000000000000000000000000000000dead",
	}
	tekuExit tekuCmd = []string{
		"voluntary-exit",
		"--confirmation-enabled=false",
		"--epoch=1",
	}
)

// startTeku starts a teku validator client for the provided node and returns updated args.
// See https://docs.teku.consensys.net/en/latest/Reference/CLI/CLI-Syntax/.
func startTeku(t *testing.T, args simnetArgs, node int) simnetArgs {
	t.Helper()

	cmd := tekuVC
	if args.VoluntaryExit {
		cmd = tekuExit
	}

	tempDir := t.TempDir()
	// Support specifying a custom base directory for docker mounts (required if running colima on macOS).
	if dir, ok := os.LookupEnv("TEST_DOCKER_DIR"); ok {
		var err error
		tempDir, err = os.MkdirTemp(dir, "")
		require.NoError(t, err)
	}

	// Write private share keystore and password
	err := keystore.StoreKeysInsecure([]tbls.PrivateKey{args.SimnetKeys[node]}, tempDir, keystore.ConfirmInsecureKeys)
	require.NoError(t, err)
	err = os.WriteFile(path.Join(tempDir, "keystore-simnet-0.txt"), []byte("simnet"), 0o644)
	require.NoError(t, err)

	// Change VAPI bind address to host external IP
	args.VAPIAddrs[node] = strings.Replace(args.VAPIAddrs[node], "127.0.0.1", externalIP(t), 1)

	var tekuArgs []string
	tekuArgs = append(tekuArgs, cmd...)
	tekuArgs = append(tekuArgs,
		"--validator-keys=/keys:/keys",
		"--beacon-node-api-endpoint=http://"+args.VAPIAddrs[node],
	)

	if args.TekuRegistration {
		tekuArgs = append(tekuArgs,
			"--validators-proposer-config-refresh-enabled=true",
			fmt.Sprintf("--validators-proposer-config=http://%s/teku_proposer_config", args.VAPIAddrs[node]),
		)
	}
	if args.BuilderAPI {
		tekuArgs = append(tekuArgs,
			"--validators-proposer-blinded-blocks-enabled=true",
		)
	}

	// Configure docker
	name := strconv.FormatInt(time.Now().UnixNano(), 10)
	dockerArgs := []string{
		"run",
		"--rm",
		"--name=" + name,
		fmt.Sprintf("--volume=%s:/keys", tempDir),
		"--user=root", // Root required to read volume files in GitHub actions.
		"consensys/teku:23.11.0",
	}
	dockerArgs = append(dockerArgs, tekuArgs...)
	t.Logf("docker args: %v", dockerArgs)

	// Start teku
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// wait for beaconmock to be available
		tout := time.After(10 * time.Second)

		bnOnline := false
		for !bnOnline {
			select {
			case <-tout:
				args.ErrChan <- errors.New("beaconmock wasn't available after 10s")
				return
			default:
				_, err := http.Get("http://" + args.VAPIAddrs[node] + "/up")
				if err != nil {
					t.Logf("beaconmock not available yet...")
					time.Sleep(500 * time.Millisecond)

					continue
				}
				bnOnline = true
				t.Logf("beaconmock online, starting up teku")
			}
		}

		c := exec.CommandContext(ctx, "docker", dockerArgs...)
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		err = c.Run()
		if err == nil || ctx.Err() != nil {
			// Expected shutdown
			return
		}
		args.ErrChan <- errors.Wrap(err, "docker command failed (see logging)")
	}()

	// Kill the container when done (context cancel is not enough for some reason).
	testutil.EnsureCleanup(t, func() {
		cancel()
		t.Log("stopping teku docker container", name)
		_ = exec.Command("docker", "kill", name).Run()
	})

	return args
}
