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

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/log"
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

//go:generate go test . -run=TestSimnetNoNetwork_TekuVC -integration -v
var integration = flag.Bool("integration", false, "Enable docker based integration test")

func TestSimnetNoNetwork_WithAttesterTekuVC(t *testing.T) {
	if !*integration {
		t.Skip("Skipping Teku integration test")
	}

	args := newSimnetArgs(t)
	args = startTeku(t, args, 0, tekuVC)
	args.BMockOpts = append(args.BMockOpts, beaconmock.WithNoProposerDuties())
	testSimnet(t, args)
}

func TestSimnetNoNetwork_WithProposerTekuVC(t *testing.T) {
	if !*integration {
		t.Skip("Skipping Teku integration test")
	}

	args := newSimnetArgs(t)
	args = startTeku(t, args, 0, tekuVC)
	args.BMockOpts = append(args.BMockOpts, beaconmock.WithNoAttesterDuties())
	testSimnet(t, args)
}

func TestSimnetNoNetwork_WithExitTekuVC(t *testing.T) {
	if !*integration {
		t.Skip("Skipping Teku integration test")
	}

	args := newSimnetArgs(t)
	for i := 0; i < args.N; i++ {
		args = startTeku(t, args, i, tekuExit)
	}
	args.BMockOpts = append(args.BMockOpts, beaconmock.WithNoAttesterDuties())
	args.BMockOpts = append(args.BMockOpts, beaconmock.WithNoProposerDuties())
	testSimnet(t, args)
}

func TestSimnetNoNetwork_WithAttesterMockVCs(t *testing.T) {
	args := newSimnetArgs(t)
	args.BMockOpts = append(args.BMockOpts, beaconmock.WithNoProposerDuties())
	testSimnet(t, args)
}

func TestSimnetNoNetwork_WithProposerMockVCs(t *testing.T) {
	args := newSimnetArgs(t)
	args.BMockOpts = append(args.BMockOpts, beaconmock.WithNoAttesterDuties())
	testSimnet(t, args)
}

type simnetArgs struct {
	N          int
	VMocks     []bool
	VAPIAddrs  []string
	P2PKeys    []*ecdsa.PrivateKey
	SimnetKeys []*bls_sig.SecretKey
	BMockOpts  []beaconmock.Option
	Lock       cluster.Lock
	ErrChan    chan error
}

// newSimnetArgs defines the default simnet test args.
func newSimnetArgs(t *testing.T) simnetArgs {
	t.Helper()

	const n = 3
	lock, p2pKeys, secretShares := cluster.NewForT(t, 1, n, n, 99)

	var secrets []*bls_sig.SecretKey
	for _, share := range secretShares[0] {
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

// testSimnet spins of a simnet cluster or N charon nodes connected via in-memory transports.
// It asserts successful end-2-end attestation broadcast from all nodes for 2 slots.
func testSimnet(t *testing.T, args simnetArgs) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())

	parSigExFunc := parsigex.NewMemExFunc()
	lcastTransportFunc := leadercast.NewMemTransportFunc(ctx)

	type simResult struct {
		Duty   core.Duty
		Pubkey core.PubKey
		Data   core.AggSignedData
	}

	var (
		eg      errgroup.Group
		results = make(chan simResult)
	)
	for i := 0; i < args.N; i++ {
		conf := app.Config{
			Log:              log.DefaultConfig(),
			Feature:          featureset.DefaultConfig(),
			SimnetBMock:      true,
			SimnetVMock:      args.VMocks[i],
			MonitoringAddr:   testutil.AvailableAddr(t).String(), // Random monitoring address
			ValidatorAPIAddr: args.VAPIAddrs[i],
			TestConfig: app.TestConfig{
				Lock:               &args.Lock,
				P2PKey:             args.P2PKeys[i],
				DisablePing:        true,
				DisablePromWrap:    true,
				SimnetKeys:         []*bls_sig.SecretKey{args.SimnetKeys[i]},
				ParSigExFunc:       parSigExFunc,
				LcastTransportFunc: lcastTransportFunc,
				BroadcastCallback: func(ctx context.Context, duty core.Duty, key core.PubKey, data core.AggSignedData) error {
					if duty.Type == core.DutyRandao {
						return nil
					}
					results <- simResult{Duty: duty, Pubkey: key, Data: data}

					return nil
				},
				SimnetBMockOpts: append([]beaconmock.Option{
					beaconmock.WithSlotsPerEpoch(1),
				}, args.BMockOpts...),
			},
			P2P: p2p.Config{},
		}

		eg.Go(func() error {
			defer cancel()
			return app.Run(ctx, conf)
		})
	}

	// Assert results
	go func() {
		var (
			remaining = 2
			counts    = make(map[core.Duty]int)
			datas     = make(map[core.Duty]core.AggSignedData)
		)
		for {
			var res simResult
			select {
			case <-ctx.Done():
				return
			case res = <-results:
			}

			require.EqualValues(t, args.Lock.Validators[0].PubKey, res.Pubkey)

			// Assert the data and signature from all nodes are the same per duty.
			if counts[res.Duty] == 0 {
				datas[res.Duty] = res.Data
			} else {
				require.Equal(t, datas[res.Duty].Data, res.Data.Data)
				require.Equal(t, datas[res.Duty].Signature, res.Data.Signature)
			}

			// Assert we get results from all peers.
			counts[res.Duty]++
			if counts[res.Duty] == args.N {
				remaining--

				if res.Duty.Type == core.DutyExit {
					remaining = 0 // DutyExit is only triggered once per node
				}
			}
			if remaining != 0 {
				continue
			}

			cancel()

			return
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
		}
	})

	err := eg.Wait()
	testutil.SkipIfBindErr(t, err)
	require.NoError(t, err)
}

type tekuCmd []string

var (
	tekuVC   tekuCmd = []string{"validator-client", "--network=auto"}
	tekuExit tekuCmd = []string{"voluntary-exit", "--confirmation-enabled=false", "--epoch=1"}
)

// startTeku starts a teku validator client for the provided node and returns updated args.
func startTeku(t *testing.T, args simnetArgs, node int, tekuCmd tekuCmd) simnetArgs {
	t.Helper()

	// Configure teku as VC for node0
	args.VMocks[node] = false

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
	tekuArgs = append(tekuArgs, tekuCmd...)
	tekuArgs = append(tekuArgs,
		"--validator-keys=/keys:/keys",
		fmt.Sprintf("--beacon-node-api-endpoint=http://%s", args.VAPIAddrs[node]),
	)

	// Configure docker
	name := fmt.Sprint(time.Now().UnixNano())
	dockerArgs := []string{
		"run",
		"--rm",
		fmt.Sprintf("--name=%s", name),
		fmt.Sprintf("--volume=%s:/keys", tempDir),
		"--user=root", // Root required to read volume files in GitHub actions.
		"consensys/teku:latest",
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
