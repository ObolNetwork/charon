// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package fuzz_test

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/compose"
)

var (
	fuzzer    = flag.Bool("fuzzer", false, "Enables docker based fuzz tests")
	sudoPerms = flag.Bool("sudo-perms", false, "Enables changing all compose artefacts file permissions using sudo.")
	logDir    = flag.String("log-dir", "", "Specifies the directory to store test docker-compose logs. Empty defaults to stdout.")
)

func TestFuzzers(t *testing.T) {
	if !*fuzzer {
		t.Skip("Skipping fuzz tests")
	}

	defaultConfig := compose.NewDefaultConfig()
	defaultConfig.DisableMonitoringPorts = true
	defaultConfig.BuildLocal = true
	defaultConfig.ImageTag = "local"
	defaultConfig.InsecureKeys = true

	tests := []struct {
		name       string
		configFunc func(compose.Config) compose.Config
		timeout    time.Duration
	}{
		{
			name: "beacon_fuzz_tests",
			configFunc: func(config compose.Config) compose.Config {
				config.BeaconFuzz = true

				return config
			},
			timeout: time.Minute * 20,
		},
		{
			name: "p2p_fuzz_tests",
			configFunc: func(config compose.Config) compose.Config {
				config.P2PFuzz = true

				return config
			},
			timeout: time.Minute * 20,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "")
			require.NoError(t, err)

			config := test.configFunc(defaultConfig)
			require.NoError(t, compose.WriteConfig(dir, config))

			os.Args = []string{"cobra.test"}

			autoConfig := compose.AutoConfig{
				Dir:          dir,
				AlertTimeout: test.timeout,
				SudoPerms:    *sudoPerms,
			}

			if *logDir != "" {
				autoConfig.LogFile = path.Join(*logDir, fmt.Sprintf("%s.log", test.name))
			}

			err = compose.Auto(context.Background(), autoConfig)
			testutil.RequireNoError(t, err)
		})
	}
}
