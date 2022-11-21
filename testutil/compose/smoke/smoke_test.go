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

package smoke_test

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/compose"
)

//go:generate go test . -run=TestSmoke -integration -v

var (
	integration    = flag.Bool("integration", false, "Enable docker based integration test")
	prebuiltBinary = flag.String("prebuilt-binary", "", "Path to a prebuilt charon binary to run inside containers")
	sudoPerms      = flag.Bool("sudo-perms", false, "Enables changing all compose artefacts file permissions using sudo.")
	logDir         = flag.String("log-dir", "", "Specifies the directory to store test docker-compose logs. Empty defaults to stdout.")
)

func TestSmoke(t *testing.T) {
	if !*integration {
		t.Skip("Skipping smoke integration test")
	}

	const defaultTimeout = time.Second * 45

	tests := []struct {
		Name           string
		ConfigFunc     func(*compose.Config)
		RunTmplFunc    func(*compose.TmplData)
		DefineTmplFunc func(*compose.TmplData)
		PrintYML       bool
		Timeout        time.Duration
	}{
		{
			Name:     "default_alpha",
			PrintYML: true,
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = compose.KeyGenCreate
				conf.FeatureSet = "alpha"
			},
		},
		{
			Name: "default_beta",
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = compose.KeyGenCreate
				conf.FeatureSet = "beta"
			},
		},
		{
			Name: "default_stable",
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = compose.KeyGenCreate
				conf.FeatureSet = "stable"
			},
		},
		{
			Name: "dkg",
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = compose.KeyGenDKG
			},
		},
		{
			Name: "very_large", // TODO(dhruv): fix consensus issues in this test
			ConfigFunc: func(conf *compose.Config) {
				conf.NumNodes = 10
				conf.Threshold = 7
				conf.NumValidators = 15
				conf.InsecureKeys = true
				conf.KeyGen = compose.KeyGenCreate
			},
			Timeout: time.Second * 120,
		},
		{
			Name:     "run_version_matrix_with_dkg",
			PrintYML: true,
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = compose.KeyGenDKG
			},
			DefineTmplFunc: func(data *compose.TmplData) {
				// v0.10.0 of charon generates v1.2.0 definition files.
				pegImageTag(data.Nodes, 0, "v0.10.0")
			},
			RunTmplFunc: func(data *compose.TmplData) {
				// Node 0 is local build
				pegImageTag(data.Nodes, 1, "latest") // TODO(corver): Update to newer release
				pegImageTag(data.Nodes, 2, "v0.10.1")
				pegImageTag(data.Nodes, 3, "v0.10.0")
			},
		},
		{
			Name: "teku_versions", // TODO(corver): Do the same for lighthouse.
			ConfigFunc: func(conf *compose.Config) {
				conf.VCs = []compose.VCType{compose.VCTeku}
			},
			RunTmplFunc: func(data *compose.TmplData) {
				data.VCs[0].Image = "consensys/teku:latest"
				data.VCs[1].Image = "consensys/teku:22.5"
				data.VCs[2].Image = "consensys/teku:22.4"
				data.VCs[3].Image = "consensys/teku:22.3"
			},
		},
		{
			Name: "1_of_4_down",
			RunTmplFunc: func(data *compose.TmplData) {
				node0 := data.Nodes[0]
				for i := 0; i < len(node0.EnvVars); i++ {
					if strings.HasPrefix(node0.EnvVars[i].Key, "p2p") {
						data.Nodes[0].EnvVars[i].Key = "unset" // Zero p2p flags to it cannot communicate
					}
				}
			},
		},
	}

	for _, test := range tests {
		test := test // Copy iterator for async usage
		t.Run(test.Name, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "")
			require.NoError(t, err)

			conf := compose.NewDefaultConfig()
			conf.DisableMonitoringPorts = true
			if *prebuiltBinary != "" {
				copyPrebuiltBinary(t, dir, *prebuiltBinary)
				conf.PrebuiltBinary = true
			}
			if test.ConfigFunc != nil {
				test.ConfigFunc(&conf)
			}
			require.NoError(t, compose.WriteConfig(dir, conf))

			os.Args = []string{"cobra.test"}

			if test.Timeout == 0 {
				test.Timeout = defaultTimeout
			}

			autoConfig := compose.AutoConfig{
				Dir:            dir,
				AlertTimeout:   test.Timeout,
				SudoPerms:      *sudoPerms,
				PrintYML:       test.PrintYML,
				RunTmplFunc:    test.RunTmplFunc,
				DefineTmplFunc: test.DefineTmplFunc,
			}

			if *logDir != "" {
				autoConfig.LogFile = path.Join(*logDir, fmt.Sprintf("%s.log", test.Name))
			}

			err = compose.Auto(context.Background(), autoConfig)
			testutil.RequireNoError(t, err)
		})
	}
}

// copyPrebuiltBinary copies the prebuilt charon binary to the compose dir.
func copyPrebuiltBinary(t *testing.T, dir string, binary string) {
	t.Helper()
	b, err := os.ReadFile(binary)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(path.Join(dir, "charon"), b, 0o555))
}

// pegImageTag pegs the charon docker image tag for one of the nodes.
// It overrides the default that uses locally built latest version.
func pegImageTag(nodes []compose.TmplNode, index int, imageTag string) {
	nodes[index].ImageTag = imageTag
	nodes[index].Entrypoint = "/usr/local/bin/charon" // Use contains binary, not locally built latest version.
}
