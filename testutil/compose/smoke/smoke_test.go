// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package smoke_test

import (
	"context"
	"flag"
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
	integration = flag.Bool("integration", false, "Enable docker based integration test")
	sudoPerms   = flag.Bool("sudo-perms", false, "Enables changing all compose artefacts file permissions using sudo.")
	logDir      = flag.String("log-dir", "", "Specifies the directory to store test docker-compose logs. Empty defaults to stdout.")
)

func TestSmoke(t *testing.T) {
	if !*integration {
		t.Skip("Skipping smoke integration test")
	}

	const defaultTimeout = time.Minute

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
				conf.VCs = []compose.VCType{compose.VCMock}
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
			Name: "1_of_4_down",
			RunTmplFunc: func(data *compose.TmplData) {
				node0 := data.Nodes[0]
				for i := range len(node0.EnvVars) {
					if strings.HasPrefix(node0.EnvVars[i].Key, "p2p") {
						data.Nodes[0].EnvVars[i].Key = node0.EnvVars[i].Key + "-unset" // Zero p2p flags to it cannot communicate
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
				for i := range len(node0.EnvVars) {
					if strings.HasPrefix(node0.EnvVars[i].Key, "p2p") {
						data.Nodes[0].EnvVars[i].Key = node0.EnvVars[i].Key + "-unset" // Zero p2p flags to it cannot communicate
					}
				}
			},
		},
		{
			Name: "blinded_blocks_vmock",
			ConfigFunc: func(conf *compose.Config) {
				conf.BuilderAPI = true
			},
		},
		{
			Name: "blinded_blocks_teku",
			ConfigFunc: func(conf *compose.Config) {
				conf.BuilderAPI = true
				conf.VCs = []compose.VCType{compose.VCTeku}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			dir := t.TempDir()

			conf := compose.NewDefaultConfig()
			conf.Monitoring = false
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
				autoConfig.LogFile = path.Join(*logDir, test.Name+".log")
			}

			err := compose.Auto(context.Background(), autoConfig)
			testutil.RequireNoError(t, err)
		})
	}
}
