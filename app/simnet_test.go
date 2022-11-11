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

package app_test

import (
	"context"
	"crypto/ecdsa"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
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
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

//go:generate go test . -integration -v
var integration = flag.Bool("integration", false, "Enable docker based integration test")

func TestSimnetDuties(t *testing.T) {
	tests := []struct {
		name                string
		bmockOpts           []beaconmock.Option
		duties              []core.DutyType
		builderAPI          bool
		builderRegistration bool
		exit                bool
		teku                bool
	}{
		{
			name: "attester with mock VCs",
			bmockOpts: []beaconmock.Option{
				beaconmock.WithNoProposerDuties(),
				beaconmock.WithNoSyncCommitteeDuties(),
			},
			duties: []core.DutyType{core.DutyPrepareAggregator, core.DutyAttester, core.DutyAggregator}, // Teku doesn't support beacon committee selection.
		},
		{
			name: "attester with teku",
			bmockOpts: []beaconmock.Option{
				beaconmock.WithNoProposerDuties(),
				beaconmock.WithNoSyncCommitteeDuties(),
			},
			duties: []core.DutyType{core.DutyAttester},
			teku:   true,
		},
		{
			name: "proposer with mock VCs",
			bmockOpts: []beaconmock.Option{
				beaconmock.WithNoAttesterDuties(),
				beaconmock.WithNoSyncCommitteeDuties(),
			},
			duties: []core.DutyType{core.DutyProposer, core.DutyRandao},
		},
		{
			name: "proposer with teku",
			bmockOpts: []beaconmock.Option{
				beaconmock.WithNoAttesterDuties(),
				beaconmock.WithNoSyncCommitteeDuties(),
			},
			duties: []core.DutyType{core.DutyProposer, core.DutyRandao},
			teku:   true,
		},
		{
			name: "builder proposer with mock VCs",
			bmockOpts: []beaconmock.Option{
				beaconmock.WithNoAttesterDuties(),
				beaconmock.WithNoSyncCommitteeDuties(),
			},
			duties:     []core.DutyType{core.DutyBuilderProposer, core.DutyRandao},
			builderAPI: true,
		},
		{
			name: "builder proposer with teku",
			bmockOpts: []beaconmock.Option{
				beaconmock.WithNoAttesterDuties(),
				beaconmock.WithNoSyncCommitteeDuties(),
			},
			duties:     []core.DutyType{core.DutyBuilderProposer, core.DutyRandao},
			builderAPI: true,
			teku:       true,
		},
		{
			name: "builder registration with mock VCs",
			bmockOpts: []beaconmock.Option{
				beaconmock.WithNoAttesterDuties(),
				beaconmock.WithNoProposerDuties(),
				beaconmock.WithNoSyncCommitteeDuties(),
			},
			duties:              []core.DutyType{core.DutyBuilderRegistration},
			builderRegistration: true,
		},
		{
			name: "builder registration with teku",
			bmockOpts: []beaconmock.Option{
				beaconmock.WithNoAttesterDuties(),
				beaconmock.WithNoProposerDuties(),
				beaconmock.WithNoSyncCommitteeDuties(),
			},
			duties:              []core.DutyType{core.DutyBuilderRegistration},
			builderRegistration: true,
			teku:                true,
		},
		{
			name: "sync committee with mock VCs",
			bmockOpts: []beaconmock.Option{
				beaconmock.WithNoAttesterDuties(),
				beaconmock.WithNoProposerDuties(),
				beaconmock.WithDeterministicSyncCommDuties(2, 2), // Always on
			},
			duties: []core.DutyType{core.DutyPrepareSyncContribution, core.DutySyncMessage, core.DutySyncContribution},
		},
		{
			name: "sync committee with teku",
			bmockOpts: []beaconmock.Option{
				beaconmock.WithNoAttesterDuties(),
				beaconmock.WithNoProposerDuties(),
				beaconmock.WithDeterministicSyncCommDuties(2, 2), // Always on
			},
			duties: []core.DutyType{core.DutySyncMessage}, // Teku doesn't support sync committee selection.
			teku:   true,
		},
		{
			name: "voluntary exit with teku",
			bmockOpts: []beaconmock.Option{
				beaconmock.WithNoAttesterDuties(),
				beaconmock.WithNoProposerDuties(),
				beaconmock.WithNoSyncCommitteeDuties(),
			},
			duties: []core.DutyType{core.DutyExit},
			exit:   true,
			teku:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.teku && !*integration {
				t.Skip("Skipping Teku integration test")
			}

			args := newSimnetArgs(t)
			args.BuilderRegistration = test.builderRegistration
			args.BuilderAPI = test.builderAPI
			args.VoluntaryExit = test.exit

			if test.teku {
				for i := 0; i < args.N; i++ {
					args = startTeku(t, args, i)
				}
			}

			args.BMockOpts = test.bmockOpts
			expect := newSimnetExpect(args.N, test.duties...)
			testSimnet(t, args, expect)
		})
	}
}

type simnetArgs struct {
	N                   int
	VMocks              []bool
	VAPIAddrs           []string
	P2PKeys             []*ecdsa.PrivateKey
	SimnetKeys          []*bls_sig.SecretKey
	BMockOpts           []beaconmock.Option
	Lock                cluster.Lock
	ErrChan             chan error
	BuilderAPI          bool
	BuilderRegistration bool
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

	var secrets []*bls_sig.SecretKey
	for _, share := range secretShares[0] { // Using only index 0 since we only have 1 DV.
		secret, err := tblsconv.ShareToSecret(share)
		require.NoError(t, err)
		secrets = append(secrets, secret)
	}

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
	counts map[core.DutyType]int
	Errs   chan error
}

// Assert tests whether the duty is expected and also updates internal counters.
func (e simnetExpect) Assert(t *testing.T, typ core.DutyType) {
	t.Helper()
	if _, ok := e.counts[typ]; !ok {
		e.Errs <- errors.New("unexpected duty type", z.Any("type", typ))
	}
	e.counts[typ]--
}

// ConsStarted returns true if all duties have been asserted sufficient number of times.
func (e simnetExpect) Done() bool {
	for _, v := range e.counts {
		if v > 0 {
			return false
		}
	}

	return true
}

// newSimnetExpect returns a new simnetExpect with all duties of equal count.
func newSimnetExpect(count int, duties ...core.DutyType) simnetExpect {
	counts := make(map[core.DutyType]int)
	for _, duty := range duties {
		counts[duty] = count
	}

	return simnetExpect{
		counts: counts,
		Errs:   make(chan error, 1),
	}
}

// testSimnet spins up a simnet cluster of N charon nodes connected via in-memory transports.
// It asserts successful end-2-end attestation broadcast from all nodes for 2 slots.
func testSimnet(t *testing.T, args simnetArgs, expect simnetExpect) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())

	parSigExFunc := parsigex.NewMemExFunc()
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
				SimnetKeys:         []*bls_sig.SecretKey{args.SimnetKeys[i]},
				ParSigExFunc:       parSigExFunc,
				LcastTransportFunc: lcastTransportFunc,
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
			P2P:        p2p.Config{},
			BuilderAPI: args.BuilderAPI,
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

			if expect.Done() {
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
		Version: spec.BuilderVersionV1,
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

	// Write private share keystore and password
	tempDir, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	err = keystore.StoreKeys([]*bls_sig.SecretKey{args.SimnetKeys[node]}, tempDir)
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
		c := exec.CommandContext(ctx, "docker", dockerArgs...)
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		err = c.Run()
		if ctx.Err() != nil {
			// Expected shutdown
			return
		}
		args.ErrChan <- errors.Wrap(err, "docker command failed (see logging)")
	}()

	// Kill the container when done (context cancel is not enough for some reason).
	t.Cleanup(func() {
		cancel()
		_ = exec.Command("docker", "kill", name).Run()
	})

	return args
}

// externalIP returns the hosts external IP.
// Copied from https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go.
func externalIP(t *testing.T) string {
	t.Helper()

	ifaces, err := net.Interfaces()
	require.NoError(t, err)

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		require.NoError(t, err)
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}

			return ip.String()
		}
	}

	t.Fatal("no network?")

	return ""
}
