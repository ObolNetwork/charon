// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
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
		Datadir       string
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
					Level:       "info",
					Format:      "console",
					Color:       "auto",
					LokiService: "charon",
				},
				P2P: p2p.Config{
					Relays:   []string{"https://0.relay.obol.tech", "https://2.relay.obol.dev", "https://1.relay.obol.tech"},
					TCPAddrs: nil,
				},
				Feature: featureset.Config{
					MinStatus: "stable",
					Enabled:   nil,
					Disabled:  nil,
				},
				LockFile:                ".charon/cluster-lock.json",
				ManifestFile:            ".charon/cluster-manifest.pb",
				PrivKeyFile:             ".charon/charon-enr-private-key",
				PrivKeyLocking:          false,
				SimnetValidatorKeysDir:  ".charon/validator_keys",
				SimnetSlotDuration:      time.Second,
				MonitoringAddr:          "127.0.0.1:3620",
				ValidatorAPIAddr:        "127.0.0.1:3600",
				OTLPAddress:             "",
				OTLPServiceName:         "charon",
				BeaconNodeAddrs:         []string{"http://beacon.node"},
				BeaconNodeTimeout:       2 * time.Second,
				BeaconNodeSubmitTimeout: 2 * time.Second,
			},
		},
		{
			Name:    "create enr",
			Args:    slice("create", "enr"),
			Datadir: ".charon",
			P2PConfig: &p2p.Config{
				Relays:   []string{"https://0.relay.obol.tech"},
				TCPAddrs: nil,
			},
		},
		{
			Name:     "run require beacon addrs",
			Args:     slice("run"),
			ErrorMsg: "either flag 'beacon-node-endpoints' or flag 'simnet-beacon-mock=true' must be specified",
		},
		{
			Name: "unsafe run",
			Args: slice("unsafe", "run", "--p2p-fuzz=true"),
			Envs: map[string]string{
				"CHARON_BEACON_NODE_ENDPOINTS": "http://beacon.node",
			},
			AppConfig: &app.Config{
				Log: log.Config{
					Level:       "info",
					Format:      "console",
					Color:       "auto",
					LokiService: "charon",
				},
				P2P: p2p.Config{
					Relays:   []string{"https://0.relay.obol.tech", "https://2.relay.obol.dev", "https://1.relay.obol.tech"},
					TCPAddrs: nil,
				},
				Feature: featureset.Config{
					MinStatus: "stable",
					Enabled:   nil,
					Disabled:  nil,
				},
				LockFile:                ".charon/cluster-lock.json",
				ManifestFile:            ".charon/cluster-manifest.pb",
				PrivKeyFile:             ".charon/charon-enr-private-key",
				PrivKeyLocking:          false,
				SimnetValidatorKeysDir:  ".charon/validator_keys",
				SimnetSlotDuration:      time.Second,
				MonitoringAddr:          "127.0.0.1:3620",
				ValidatorAPIAddr:        "127.0.0.1:3600",
				OTLPAddress:             "",
				OTLPServiceName:         "charon",
				BeaconNodeAddrs:         []string{"http://beacon.node"},
				BeaconNodeTimeout:       2 * time.Second,
				BeaconNodeSubmitTimeout: 2 * time.Second,
				TestConfig: app.TestConfig{
					P2PFuzz: true,
				},
			},
		},
		{
			Name:     "run with unsafe flags, unknown flags",
			Args:     slice("run", "--charon-p2p-fuzz=true"),
			ErrorMsg: "unknown flag: --charon-p2p-fuzz",
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
				}, false),
				newCreateCmd(
					newCreateEnrCmd(func(_ io.Writer, datadir string) error {
						require.Equal(t, test.Datadir, datadir)

						return nil
					}),
				),
				newUnsafeCmd(newRunCmd(func(_ context.Context, config app.Config) error {
					require.NotNil(t, test.AppConfig)
					require.Equal(t, *test.AppConfig, config)

					return nil
				}, true)),
			)

			// Set envs (only for duration of the test)
			for k, v := range test.Envs {
				t.Setenv(k, v)
			}

			_ = testutil.CreateTempCharonDir(t)
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

func TestFlagsToLogFields(t *testing.T) {
	set := pflag.NewFlagSet("test", pflag.PanicOnError)
	bindLokiFlags(set, &log.Config{})
	err := set.Parse([]string{
		"--loki-addresses=https://user:password@loki.tech/push",
	})
	require.NoError(t, err)

	for _, field := range flagsToLogFields(set) {
		field(func(f zap.Field) {
			require.NotContains(t, f.String, "password")
		})
	}
}

func TestRedact(t *testing.T) {
	tests := []struct {
		name     string
		flag     string
		value    string
		expected string
	}{
		{
			name:     "redact auth tokens",
			flag:     "keymanager-auth-token",
			value:    "api-token-abcdef12345",
			expected: "xxxxx",
		},
		{
			name:     "redact passwords in URL addresses",
			flag:     "api-address",
			value:    "https://user:password@example.com/foo/bar",
			expected: "https://user:xxxxx@example.com/foo/bar",
		},
		{
			name:     "no redact",
			flag:     "definition-file",
			value:    "https://obol.obol.tech/dv/0x0f481bbd06a596cb3ba569b9de0cbfcf822b209c2d6877c98173df986dd3c0ec",
			expected: "https://obol.obol.tech/dv/0x0f481bbd06a596cb3ba569b9de0cbfcf822b209c2d6877c98173df986dd3c0ec",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redact(tt.flag, tt.value)
			require.Equal(t, tt.expected, got)
		})
	}
}

// slice is a convenience function for creating string slice literals.
func slice(strs ...string) []string {
	return strs
}
