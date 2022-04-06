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
		Datadir       string
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
			Envs: map[string]string{"CHARON_DATA_DIR": "from_env"},
			AppConfig: &app.Config{
				Log: log.Config{
					Level:  "info",
					Format: "console",
				},
				P2P: p2p.Config{
					UDPAddr:   "127.0.0.1:30309",
					TCPAddrs:  []string{"127.0.0.1:13900"},
					Allowlist: "",
					Denylist:  "",
					DBPath:    "",
				},
				ManifestFile:     "./charon/manifest.json",
				DataDir:          "from_env",
				MonitoringAddr:   "127.0.0.1:8088",
				ValidatorAPIAddr: "127.0.0.1:3500",
				BeaconNodeAddr:   "http://localhost/",
				JaegerAddr:       "",
				JaegerService:    "charon",
			},
		},
		{
			Name:    "gen p2p",
			Args:    slice("gen-p2pkey"),
			Datadir: "./charon/data",
			P2PConfig: &p2p.Config{
				UDPAddr:   "127.0.0.1:30309",
				TCPAddrs:  []string{"127.0.0.1:13900"},
				Allowlist: "",
				Denylist:  "",
				DBPath:    "",
			},
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
				newGenP2PKeyCmd(func(_ io.Writer, config p2p.Config, datadir string) error {
					require.NotNil(t, test.P2PConfig)
					require.Equal(t, *test.P2PConfig, config)
					require.Equal(t, test.Datadir, datadir)

					return nil
				}),
			)

			// Set envs (only for duration of the test)
			for k, v := range test.Envs {
				require.NoError(t, os.Setenv(k, v))
			}
			t.Cleanup(func() {
				for k := range test.Envs {
					require.NoError(t, os.Unsetenv(k))
				}
			})

			root.SetArgs(test.Args)
			require.NoError(t, root.Execute())
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
