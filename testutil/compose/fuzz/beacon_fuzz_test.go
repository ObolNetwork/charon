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

//go:generate go test . -run=TestBeaconFuzz -integration -v

var (
	beaconFuzz  = flag.Bool("beacon-fuzz", false, "Enable docker based integration test")
	sudoPerms   = flag.Bool("sudo-perms", false, "Enables changing all compose artefacts file permissions using sudo.")
	logDir      = flag.String("log-dir", "", "Specifies the directory to store test docker-compose logs. Empty defaults to stdout.")
	fuzzTimeout = flag.Duration("timeout", time.Minute*10, "Specifies the duration of the beacon fuzz test.")
)

func TestBeaconFuzz(t *testing.T) {
	if !*beaconFuzz {
		t.Skip("Skipping beacon fuzz integration test")
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
