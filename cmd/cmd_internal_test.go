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

package cmd

import (
	"bytes"
	"context"
	"flag"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/p2p"
)

func TestCmdFlags(t *testing.T) {
	tests := []struct {
		Name          string
		Args          []string
		VersionConfig *versionConfig
		AppConfig     *app.Config
		P2PConfig     *p2p.Config
		Envs          map[string]string
		PrivKeyFile   string
		ErrorMsg      string
	}{
		{
			Name:          "version verbose",
			Args:          slice("version", "--verbose"),
			VersionConfig: &versionConfig{Verbose: true},
		},
		{
			Name:          "version no verbose",
			Args:          slice("version", "--verbose=false"),
			VersionConfig: &versionConfig{Verbose: false},
		},
		{
			Name:          "version verbose env",
			Args:          slice("version"),
			Envs:          map[string]string{"CHARON_VERBOSE": "true"},
			VersionConfig: &versionConfig{Verbose: true},
		},
		{
			Name: "run command",
			Args: slice("run"),
			Envs: map[string]string{
				"CHARON_BEACON_NODE_ENDPOINTS": "http://beacon.node",
			},
			AppConfig: &app.Config{
				Log: log.Config{
					Level:  "info",
					Format: "console",
				},
				P2P: p2p.Config{
					UDPBootnodes: []string{"http://bootnode.lb.gcp.obol.tech:3640/enr"},
					UDPAddr:      "127.0.0.1:3630",
					TCPAddrs:     []string{"127.0.0.1:3610"},
					Allowlist:    "",
					Denylist:     "",
				},
				Feature: featureset.Config{
					MinStatus: "stable",
					Enabled:   nil,
					Disabled:  nil,
				},
				LockFile:            ".charon/cluster-lock.json",
				PrivKeyFile:         ".charon/charon-enr-private-key",
				SimnetValidatorKeys: ".charon/validator_keys",
				MonitoringAddr:      "127.0.0.1:3620",
				ValidatorAPIAddr:    "127.0.0.1:3600",
				BeaconNodeAddrs:     []string{"http://beacon.node"},
				JaegerAddr:          "",
				JaegerService:       "charon",
			},
		},
		{
			Name:        "create enr",
			Args:        slice("create", "enr"),
			PrivKeyFile: ".charon/charon-enr-private-key",
			P2PConfig: &p2p.Config{
				UDPBootnodes: []string{"http://bootnode.lb.gcp.obol.tech:3640/enr"},
				UDPAddr:      "127.0.0.1:3630",
				TCPAddrs:     []string{"127.0.0.1:3610"},
				Allowlist:    "",
				Denylist:     "",
			},
		},
		{
			Name:     "run require beacon addrs",
			Args:     slice("run"),
			ErrorMsg: "either flag 'beacon-node-endpoints' or flag 'simnet-beacon-mock=true' must be specified",
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			root := newRootCmd(
				newVersionCmd(func(_ io.Writer, config versionConfig) {
					require.NotNil(t, test.VersionConfig)
					require.Equal(t, *test.VersionConfig, config)
				}),
				newRunCmd(func(_ context.Context, config app.Config) error {
					require.NotNil(t, test.AppConfig)
					require.Equal(t, *test.AppConfig, config)

					return nil
				}),
				newCreateCmd(
					newCreateEnrCmd(func(_ io.Writer, config p2p.Config, privKeyFile string) error {
						require.NotNil(t, test.P2PConfig)
						require.Equal(t, *test.P2PConfig, config)
						require.Equal(t, test.PrivKeyFile, privKeyFile)
						return nil
					}),
				),
			)

			// Set envs (only for duration of the test)
			for k, v := range test.Envs {
				require.NoError(t, os.Setenv(k, v))
			}

			require.NoError(t, os.Mkdir(".charon", 0o755))
			defer func() {
				require.NoError(t, os.RemoveAll(".charon"))
			}()
			if test.AppConfig != nil {
				_, err := p2p.NewSavedPrivKey(test.AppConfig.PrivKeyFile)
				require.NoError(t, err)
			}

			t.Cleanup(func() {
				for k := range test.Envs {
					require.NoError(t, os.Unsetenv(k))
				}
			})

			root.SetArgs(test.Args)
			if test.ErrorMsg != "" {
				require.ErrorContains(t, root.Execute(), test.ErrorMsg)
			} else {
				require.NoError(t, root.Execute())
			}
		})
	}
}

var update = flag.Bool("update_conf", false, "Updates the config reference doc")

//go:generate go test . -run=TestConfigReference -update_conf

// TestConfigReference ensures that docs/configuration.md contains the latest output of `charon run --help`.
// Running this test with the --update_conf flag will generate the contents, fixing the test if broken.
func TestConfigReference(t *testing.T) {
	cmd := newRootCmd(newRunCmd(func(context.Context, app.Config) error {
		return nil
	}))

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs(slice("run", "--help"))

	require.NoError(t, cmd.Execute())

	file := "../docs/configuration.md"

	content, err := os.ReadFile(file)
	require.NoError(t, err)

	if *update {
		var (
			output   []string
			skipping bool
		)
		for _, line := range strings.Split(string(content), "\n") {
			if strings.Contains(line, "Code above generated by") {
				skipping = false
			}

			if skipping {
				continue
			}

			output = append(output, line)

			if strings.Contains(line, "Code below generated by") {
				skipping = true
				output = append(output, "````")
				output = append(output, strings.Split(buf.String(), "\n")...)
				output = append(output, "````")
			}
		}

		err = os.WriteFile(file, []byte(strings.Join(output, "\n")), 0o644)
		require.NoError(t, err)

		return
	}

	require.Containsf(t, string(content), buf.String(),
		"docs/configuration.md doesn't contain latest `charon run --help` output. "+
			"Run with -update_conf to fix")
}

// slice is a convenience function for creating string slice literals.
func slice(strs ...string) []string {
	return strs
}
