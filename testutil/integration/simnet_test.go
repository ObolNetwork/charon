// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
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
	"github.com/obolnetwork/charon/core/leadercast"
	"github.com/obolnetwork/charon/core/parsigex"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/p2p"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

//go:generate go test . -integration -v -run=TestSimnetDuties

func TestSimnetDuties(t *testing.T) {
	skipIfDisabled(t)

	tests := []struct {
		name                string
		scheduledType       core.DutyType
		duties              []core.DutyType
		builderAPI          bool
		builderRegistration bool
		exit                bool
		teku                bool
	}{
		{
			name:          "attester with mock VCs",
			scheduledType: core.DutyAttester,
			duties:        []core.DutyType{core.DutyPrepareAggregator, core.DutyAttester, core.DutyAggregator},
		},
		{
			name:          "attester with teku",
			scheduledType: core.DutyAttester,
			duties:        []core.DutyType{core.DutyAttester}, // Teku does not support beacon committee selection
			teku:          true,
		},
		{
			name:          "proposer with mock VCs",
			scheduledType: core.DutyProposer,
			duties:        []core.DutyType{core.DutyProposer, core.DutyRandao},
		},
		{
			name:          "proposer with teku",
			scheduledType: core.DutyProposer,
			duties:        []core.DutyType{core.DutyProposer, core.DutyRandao},
			teku:          true,
		},
		{
			name:          "builder proposer with mock VCs",
			scheduledType: core.DutyProposer,
			duties:        []core.DutyType{core.DutyBuilderProposer, core.DutyRandao},
			builderAPI:    true,
		},
		{
			name:          "builder proposer with teku",
			scheduledType: core.DutyProposer,
			duties:        []core.DutyType{core.DutyBuilderProposer, core.DutyRandao},
			builderAPI:    true,
			teku:          true,
		},
		{
			name:                "builder registration with mock VCs",
			scheduledType:       0,
			duties:              []core.DutyType{core.DutyBuilderRegistration},
			builderRegistration: true,
			builderAPI:          true,
		},
		{
			name:                "builder registration with teku",
			scheduledType:       0,
			duties:              []core.DutyType{core.DutyBuilderRegistration},
			builderRegistration: true,
			builderAPI:          true,
			teku:                true,
		},
		{
			name:          "sync committee with mock VCs",
			scheduledType: core.DutySyncMessage,
			duties:        []core.DutyType{core.DutyPrepareSyncContribution, core.DutySyncMessage, core.DutySyncContribution},
		},
		{
			name:          "sync committee with teku",
			scheduledType: core.DutySyncMessage,
			duties:        []core.DutyType{core.DutySyncMessage}, // Teku doesn't support sync committee selection.
			teku:          true,
		},
		{
			name:          "voluntary exit with teku",
			scheduledType: 0,
			duties:        []core.DutyType{core.DutyExit},
			exit:          true,
			teku:          true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Logf("Running test: %v", t.Name())

			args := newSimnetArgs(t)
			args.BuilderRegistration = test.builderRegistration
			args.BuilderAPI = test.builderAPI
			args.VoluntaryExit = test.exit

			if test.teku {
				for i := 0; i < args.N; i++ {
					args = startTeku(t, args, i)
				}
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
	N                   int
	VMocks              []bool
	VAPIAddrs           []string
	P2PKeys             []*k1.PrivateKey
	SimnetKeys          []tblsv2.PrivateKey
	BMockOpts           []beaconmock.Option
	Lock                cluster.Lock
	ErrChan             chan error
	BuilderAPI          bool
	BuilderRegistration bool
	SyntheticProposals  bool
	VoluntaryExit       bool
}

// newSimnetArgs defines the default simnet test args.
func newSimnetArgs(t *testing.T) simnetArgs {
	t.Helper()

	const (
		n      = 3
		numDVs = 1
	)
	lock, p2pKeys, secretShares := cluster.NewForT(t, numDVs, n, n, 99)

	secrets := secretShares[0]

	var (
		vmocks    []bool
		vapiAddrs []string
	)
	for i := 0; i < n; i++ {
		vmocks = append(vmocks, true)
		vapiAddrs = append(vapiAddrs, testutil.AvailableAddr(t).String())
	}

	return simnetArgs{
		N:          n,
		VMocks:     vmocks,
		VAPIAddrs:  vapiAddrs,
		P2PKeys:    p2pKeys,
		SimnetKeys: secrets,
		Lock:       lock,
		ErrChan:    make(chan error, 1),
	}
}

// simnetExpect defines which duties (including how many of each) are expected in simnet tests.
type simnetExpect struct {
	mu     sync.Mutex
	counts map[core.DutyType]int
	Errs   chan error
}

// Assert tests whether the duty is expected and also updates internal counters.
func (e *simnetExpect) Assert(t *testing.T, typ core.DutyType) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.counts[typ]; !ok {
		t.Logf("unexpected duty, type=%v", typ)
		e.Errs <- errors.New("unexpected duty type", z.Any("type", typ))
	}
	e.counts[typ]--
	t.Logf("asserted duty, type=%v, remaining=%d", typ, e.counts[typ])
}

// Done returns true if all duties have been asserted sufficient number of times.
func (e *simnetExpect) Done(t *testing.T) bool {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()

	for k, v := range e.counts {
		if v > 0 {
			t.Logf("assertion not done yet, duty type=%v, remaining=%d", k, v)
			return false
		}
	}
	t.Logf("assertion done, no duties remaining")

	return true
}

// newSimnetExpect returns a new simnetExpect with all duties of equal count.
func newSimnetExpect(count int, duties ...core.DutyType) *simnetExpect {
	counts := make(map[core.DutyType]int)
	for _, duty := range duties {
		counts[duty] = count
	}

	return &simnetExpect{
		counts: counts,
		Errs:   make(chan error, 1),
	}
}

// testSimnet spins up a simnet cluster of N charon nodes connected via in-memory transports.
// It asserts successful end-2-end attestation broadcast from all nodes for 2 slots.
func testSimnet(t *testing.T, args simnetArgs, expect *simnetExpect) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())

	parSigExFunc := parsigex.NewMemExFunc(args.N)
	lcastTransportFunc := leadercast.NewMemTransportFunc(ctx)
	featureConf := featureset.DefaultConfig()
	featureConf.Disabled = []string{string(featureset.QBFTConsensus)} // TODO(corver): Add support for in-memory transport to QBFT.
	registrationFunc := newRegistrationProvider(t, args)

	type simResult struct {
		Duty   core.Duty
		Pubkey core.PubKey
		Data   core.SignedData
	}

	var (
		eg      errgroup.Group
		results = make(chan simResult)
	)
	for i := 0; i < args.N; i++ {
		conf := app.Config{
			Log:              log.DefaultConfig(),
			Feature:          featureConf,
			SimnetBMock:      true,
			SimnetVMock:      args.VMocks[i],
			MonitoringAddr:   testutil.AvailableAddr(t).String(), // Random monitoring address
			ValidatorAPIAddr: args.VAPIAddrs[i],
			TestConfig: app.TestConfig{
				Lock:               &args.Lock,
				P2PKey:             args.P2PKeys[i],
				TestPingConfig:     p2p.TestPingConfig{Disable: true},
				SimnetKeys:         []tblsv2.PrivateKey{args.SimnetKeys[i]},
				LcastTransportFunc: lcastTransportFunc,
				ParSigExFunc:       parSigExFunc,
				BroadcastCallback: func(_ context.Context, duty core.Duty, key core.PubKey, data core.SignedData) error {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case results <- simResult{Duty: duty, Pubkey: key, Data: data}:
						return nil
					}
				},
				SimnetBMockOpts: append([]beaconmock.Option{
					beaconmock.WithSlotsPerEpoch(1),
				}, args.BMockOpts...),
				BuilderRegistration: registrationFunc(),
			},
			P2P:                     p2p.Config{},
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
			expect.Assert(t, res.Duty.Type)

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

// newRegistrationProvider returns a function that provides identical registration structs for
// the first validator in the lock file.
func newRegistrationProvider(t *testing.T, args simnetArgs) func() <-chan *eth2api.VersionedValidatorRegistration {
	t.Helper()

	pubkey, err := core.PubKey(args.Lock.Validators[0].PublicKeyHex()).ToETH2()
	require.NoError(t, err)
	reg := &eth2api.VersionedValidatorRegistration{
		Version: eth2spec.BuilderVersionV1,
		V1: &eth2v1.ValidatorRegistration{
			FeeRecipient: testutil.RandomExecutionAddress(),
			GasLimit:     99,
			Timestamp:    time.Now(),
			Pubkey:       pubkey,
		},
	}

	return func() <-chan *eth2api.VersionedValidatorRegistration {
		if !args.BuilderRegistration {
			return nil
		}
		regChan := make(chan *eth2api.VersionedValidatorRegistration, 1)
		regChan <- reg

		return regChan
	}
}

type tekuCmd []string

var (
	tekuVC tekuCmd = []string{
		"validator-client",
		"--network=auto",
		"--log-destination=console",
		"--beacon-node-ssz-blocks-enabled=false",
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

	// Configure teku as VC for node0
	args.VMocks[node] = false

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
	err := keystore.StoreKeysInsecure([]tblsv2.PrivateKey{args.SimnetKeys[node]}, tempDir, keystore.ConfirmInsecureKeys)
	require.NoError(t, err)
	err = os.WriteFile(path.Join(tempDir, "keystore-simnet-0.txt"), []byte("simnet"), 0o644)
	require.NoError(t, err)

	// Change VAPI bind address to host external IP
	args.VAPIAddrs[node] = strings.Replace(args.VAPIAddrs[node], "127.0.0.1", externalIP(t), 1)

	var tekuArgs []string
	tekuArgs = append(tekuArgs, cmd...)
	tekuArgs = append(tekuArgs,
		"--validator-keys=/keys:/keys",
		fmt.Sprintf("--beacon-node-api-endpoint=http://%s", args.VAPIAddrs[node]),
	)

	if args.BuilderRegistration {
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
	name := fmt.Sprint(time.Now().UnixNano())
	dockerArgs := []string{
		"run",
		"--rm",
		fmt.Sprintf("--name=%s", name),
		fmt.Sprintf("--volume=%s:/keys", tempDir),
		"--user=root", // Root required to read volume files in GitHub actions.
		"consensys/teku:develop",
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
				_, err := http.Get("http://" + args.VAPIAddrs[node])
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
