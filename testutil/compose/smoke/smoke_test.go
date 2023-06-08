// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/compose"
)

//go:generate go test . -run=TestSmoke -integration -v

var (
	integration = flag.Bool("integration", false, "Enable docker based integration test")
	sudoPerms   = flag.Bool("sudo-perms", false, "Enables changing all compose artefacts file permissions using sudo.")
	logDir      = flag.String("log-dir", "", "Specifies the directory to store test docker-compose logs. Empty defaults to stdout.")
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
				conf.NumNodes = 3
				conf.Threshold = 2
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
			Name: "very_large",
			ConfigFunc: func(conf *compose.Config) {
				conf.NumNodes = 10
				conf.Threshold = 7
				conf.NumValidators = 100
				conf.KeyGen = compose.KeyGenCreate
				conf.VCs = []compose.VCType{compose.VCMock}
				conf.SlotDuration = time.Second * 6
				conf.SyntheticBlockProposals = false
			},
			Timeout: time.Minute * 2,
		},
		{
			Name:     "run_version_matrix_with_dkg",
			PrintYML: true,
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = compose.KeyGenDKG
				conf.VCs = []compose.VCType{compose.VCMock} // TODO(dhruv): add external VCs when supported versions include minimal preset.
			},
			DefineTmplFunc: func(data *compose.TmplData) {
				// Use oldest supported version for cluster lock
				pegImageTag(data.Nodes, 0, last(version.Supported()[1:])+".0")
			},
			RunTmplFunc: func(data *compose.TmplData) {
				// Node 0 is local build
				pegImageTag(data.Nodes, 1, version.Version.String()) // Node 1 is previous commit on this branch (v0.X-dev/rc) Note this will fail for first commit on new branch version.
				pegImageTag(data.Nodes, 2, nth(version.Supported()[1:], 1)+".0")
				pegImageTag(data.Nodes, 3, nth(version.Supported()[1:], 2)+".0")
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
		{
			Name: "1_of_3_down",
			ConfigFunc: func(conf *compose.Config) {
				conf.NumNodes = 3
				conf.Threshold = 2
			},
			RunTmplFunc: func(data *compose.TmplData) {
				node0 := data.Nodes[0]
				for i := 0; i < len(node0.EnvVars); i++ {
					if strings.HasPrefix(node0.EnvVars[i].Key, "p2p") {
						data.Nodes[0].EnvVars[i].Key = "unset" // Zero p2p flags to it cannot communicate
					}
				}
			},
		},
		{
			Name: "cluster_with_vouch",
			ConfigFunc: func(conf *compose.Config) {
				conf.VCs = []compose.VCType{compose.VCVouch}
			},
		},
		{
			Name: "cluster_with_lodestar",
			ConfigFunc: func(conf *compose.Config) {
				conf.VCs = []compose.VCType{compose.VCLodestar}
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
			conf.BuildLocal = true
			conf.ImageTag = "local"
			conf.InsecureKeys = true
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

// pegImageTag pegs the charon docker image tag for one of the nodes.
// It overrides the default that uses locally built latest version.
func pegImageTag(nodes []compose.TmplNode, index int, imageTag string) {
	nodes[index].ImageTag = imageTag
	nodes[index].Entrypoint = "/usr/local/bin/charon" // Use contains binary, not locally built latest version.
}

// last returns the last element of a slice.
func last(s []version.SemVer) string {
	return s[len(s)-1].String()
}

// nth returns the nth element of a slice, wrapping if n > len(s).
func nth(s []version.SemVer, n int) string {
	return s[n%len(s)].String()
}
