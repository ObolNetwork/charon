// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	fuzzer      = flag.Bool("fuzzer", false, "Enables docker based fuzzer tests")
	sudoPerms   = flag.Bool("sudo-perms", false, "Enables changing all compose artefacts file permissions using sudo.")
	logDir      = flag.String("log-dir", "", "Specifies the directory to store test docker-compose logs. Empty defaults to stdout.")
	fuzzTimeout = flag.Duration("timeout", time.Minute*10, "Specifies the duration of the beacon fuzzer test.")
)

func TestBeaconFuzz(t *testing.T) {
	if !*fuzzer {
		t.Skip("Skipping beacon fuzzer integration test")
	}

	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	conf := compose.NewDefaultConfig()
	conf.SyntheticBlockProposals = true
	conf.Fuzz = true
	conf.DisableMonitoringPorts = true
	conf.BuildLocal = true
	conf.ImageTag = "local"
	conf.InsecureKeys = true
	require.NoError(t, compose.WriteConfig(dir, conf))

	os.Args = []string{"cobra.test"}

	autoConfig := compose.AutoConfig{
		Dir:          dir,
		AlertTimeout: *fuzzTimeout,
		SudoPerms:    *sudoPerms,
	}

	if *logDir != "" {
		autoConfig.LogFile = path.Join(*logDir, fmt.Sprintf("%s.log", t.Name()))
	}

	err = compose.Auto(context.Background(), autoConfig)
	testutil.RequireNoError(t, err)
}

func TestP2PFuzz(t *testing.T) {
	if !*fuzzer {
		t.Skip("Skipping p2p fuzzer integration test")
	}

	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	conf := compose.NewDefaultConfig()
	conf.DisableMonitoringPorts = true
	conf.BuildLocal = true
	conf.P2PFuzz = true
	conf.ImageTag = "local"
	conf.InsecureKeys = true
	require.NoError(t, compose.WriteConfig(dir, conf))

	os.Args = []string{"cobra.test"}

	autoConfig := compose.AutoConfig{
		Dir:          dir,
		AlertTimeout: *fuzzTimeout,
		SudoPerms:    *sudoPerms,
	}

	if *logDir != "" {
		autoConfig.LogFile = path.Join(*logDir, fmt.Sprintf("%s.log", t.Name()))
	}

	err = compose.Auto(context.Background(), autoConfig)
	testutil.RequireNoError(t, err)
}
