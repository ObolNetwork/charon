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

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil/compose"
)

//go:generate go test . -run=TestSmoke -integration -v

var (
	integration    = flag.Bool("integration", false, "Enable docker based integration test")
	prebuiltBinary = flag.String("prebuilt-binary", "", "Path to a prebuilt charon binary to run inside containers")
	sudoPerms      = flag.Bool("sudo-perms", false, "Enables changing all compose artefacts file permissions using sudo.")
)

func TestSmoke(t *testing.T) {
	if !*integration {
		t.Skip("Skipping smoke integration test")
	}

	tests := []struct {
		Name           string
		ConfigFunc     func(*compose.Config)
		RunTmplFunc    func(*compose.TmplData)
		DefineTmplFunc func(*compose.TmplData)
	}{
		{
			Name: "default alpha",
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = compose.KeyGenCreate
				conf.FeatureSet = "alpha"
			},
		},
		{
			Name: "default beta",
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = compose.KeyGenCreate
				conf.FeatureSet = "beta"
			},
		},
		{
			Name: "default stable",
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
			Name: "very large",
			ConfigFunc: func(conf *compose.Config) {
				conf.NumNodes = 21
				conf.Threshold = 14
				conf.NumValidators = 1000
				conf.KeyGen = compose.KeyGenCreate
			},
		},
		{
			Name: "run version matrix with dkg",
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = compose.KeyGenDKG
			},
			RunTmplFunc: func(data *compose.TmplData) {
				// Node 0 is latest
				pegImageTag(data.Nodes, 1, "v8.0.0")
				pegImageTag(data.Nodes, 2, "v7.0.0")
				pegImageTag(data.Nodes, 3, "v6.0.0")
			},
		},
		{
			Name: "definition version matrix with dkg - v1.0.0",
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = compose.KeyGenDKG
			},
			DefineTmplFunc: func(data *compose.TmplData) {
				// v8.0.0 of charon generates v1.0.0 defnition files.
				pegImageTag(data.Nodes, 0, "v8.0.0")
			},
		},
		{
			Name: "teku versions", // TODO(corver): Do the same for lighthouse.
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
			Name: "1 of 4 down",
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
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			dir, err := os.MkdirTemp("", "")
			require.NoError(t, err)

			conf := compose.NewDefaultConfig()
			conf.MonitoringPorts = false
			if *prebuiltBinary != "" {
				copyPrebuiltBinary(t, dir, *prebuiltBinary)
				conf.PrebuiltBinary = true
			}
			if test.ConfigFunc != nil {
				test.ConfigFunc(&conf)
			}
			require.NoError(t, compose.WriteConfig(dir, conf))

			cmd := newAutoCmd(map[string]func(data *compose.TmplData){
				"define": test.DefineTmplFunc,
				"run":    test.RunTmplFunc,
			})
			require.NoError(t, cmd.Flags().Set("compose-dir", dir))
			require.NoError(t, cmd.Flags().Set("alert-timeout", "30s"))
			require.NoError(t, cmd.Flags().Set("sudo-perms", fmt.Sprint(*sudoPerms)))
			require.NoError(t, cmd.Flags().Set("print-yml", "true"))

			os.Args = []string{"cobra.test"}

			err = cmd.ExecuteContext(context.Background())
			require.NoError(t, err)
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
