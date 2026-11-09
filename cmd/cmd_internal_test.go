// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/dkg"
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
					Relays:   []string{"https://0.relay.obol.tech", "https://1.relay.obol.tech", "https://2.relay.obol.dev"},
					TCPAddrs: nil,
				},
				Feature: featureset.Config{
					MinStatus: "stable",
					Enabled:   nil,
					Disabled:  nil,
				},
				LockFile:                    ".charon/cluster-lock.json",
				ManifestFile:                ".charon/cluster-manifest.pb",
				PrivKeyFile:                 ".charon/charon-enr-private-key",
				PrivKeyLocking:              false,
				SimnetValidatorKeysDir:      ".charon/validator_keys",
				SimnetSlotDuration:          time.Second,
				MonitoringAddr:              "127.0.0.1:3620",
				ValidatorAPIAddr:            "127.0.0.1:3600",
				OTLPAddress:                 "",
				OTLPServiceName:             "charon",
				BeaconNodeAddrs:             []string{"http://beacon.node"},
				BeaconNodeTimeout:           2 * time.Second,
				BeaconNodeSubmitTimeout:     2 * time.Second,
				BuilderRegOverridesFilePath: ".charon/builder_registrations_overrides.json",
				PublishAddress:              "https://api.obol.tech/v1",
				PublishTimeout:              5 * time.Minute,
				ProposerConfigFile:          ".charon/vc-config/proposer-config.json",
				ProposerConfigSeed:          proposerconfig.Seed{GasLimit: 200_000_000, BuilderBoostFactor: 100},
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
					Relays:   []string{"https://0.relay.obol.tech", "https://1.relay.obol.tech", "https://2.relay.obol.dev"},
					TCPAddrs: nil,
				},
				Feature: featureset.Config{
					MinStatus: "stable",
					Enabled:   nil,
					Disabled:  nil,
				},
				LockFile:                    ".charon/cluster-lock.json",
				ManifestFile:                ".charon/cluster-manifest.pb",
				PrivKeyFile:                 ".charon/charon-enr-private-key",
				PrivKeyLocking:              false,
				SimnetValidatorKeysDir:      ".charon/validator_keys",
				SimnetSlotDuration:          time.Second,
				MonitoringAddr:              "127.0.0.1:3620",
				ValidatorAPIAddr:            "127.0.0.1:3600",
				OTLPAddress:                 "",
				OTLPServiceName:             "charon",
				BeaconNodeAddrs:             []string{"http://beacon.node"},
				BeaconNodeTimeout:           2 * time.Second,
				BeaconNodeSubmitTimeout:     2 * time.Second,
				BuilderRegOverridesFilePath: ".charon/builder_registrations_overrides.json",
				PublishAddress:              "https://api.obol.tech/v1",
				PublishTimeout:              5 * time.Minute,
				ProposerConfigFile:          ".charon/vc-config/proposer-config.json",
				ProposerConfigSeed:          proposerconfig.Seed{GasLimit: 200_000_000, BuilderBoostFactor: 100},
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

func TestProposerConfigSeedFlags(t *testing.T) {
	execute := func(t *testing.T, args ...string) (app.Config, error) {
		t.Helper()

		var conf app.Config

		root := newRootCmd(newRunCmd(func(_ context.Context, config app.Config) error {
			conf = config
			return nil
		}, false))
		root.SetArgs(append([]string{"run", "--beacon-node-endpoints=http://beacon.node"}, args...))

		return conf, root.Execute()
	}

	t.Run("new flags parse", func(t *testing.T) {
		conf, err := execute(t,
			"--proposer-config-file=pc.json",
			"--proposer-config-gas-limit=60000000",
			"--proposer-config-builder-urls=https://a.example.com,https://b.example.com",
			"--proposer-config-builder-min-bid=1",
			"--proposer-config-builder-boost-factor=90",
			"--proposer-config-builder-max-execution-payment=2",
		)
		require.NoError(t, err)
		require.Equal(t, "pc.json", conf.ProposerConfigFile)
		require.Equal(t, proposerconfig.Seed{
			GasLimit:                   60_000_000,
			BuilderURLs:                []string{"https://a.example.com", "https://b.example.com"},
			BuilderMinBid:              1,
			BuilderBoostFactor:         90,
			BuilderMaxExecutionPayment: 2,
			NonDefault: []string{
				"proposer-config-gas-limit", "proposer-config-builder-urls", "proposer-config-builder-min-bid",
				"proposer-config-builder-boost-factor", "proposer-config-builder-max-execution-payment",
			},
		}, conf.ProposerConfigSeed)
	})

	for _, flag := range []string{"proposer-gas-limit", "builder-urls", "builder-min-bid", "builder-boost-factor", "builder-max-execution-payment"} {
		t.Run("old flag "+flag, func(t *testing.T) {
			_, err := execute(t, "--"+flag+"=1")
			require.ErrorContains(t, err, "unknown flag: --"+flag)
		})
	}

	t.Run("builder value without urls", func(t *testing.T) {
		_, err := execute(t, "--proposer-config-builder-min-bid=1")
		require.ErrorContains(t, err, "require proposer-config-builder-urls")
	})

	t.Run("boost factor without urls", func(t *testing.T) {
		_, err := execute(t, "--proposer-config-builder-boost-factor=100")
		require.ErrorContains(t, err, "require proposer-config-builder-urls")
	})

	t.Run("zero gas limit", func(t *testing.T) {
		_, err := execute(t, "--proposer-config-gas-limit=0")
		require.ErrorContains(t, err, "proposer-config-gas-limit must be greater than 0")
	})
}

func TestDKGProposerConfigSeedFlags(t *testing.T) {
	execute := func(t *testing.T, args ...string) (dkg.Config, error) {
		t.Helper()

		var conf dkg.Config

		root := newRootCmd(newDKGCmd(func(_ context.Context, config dkg.Config) error {
			conf = config
			return nil
		}))
		root.SetArgs(append([]string{"dkg"}, args...))

		return conf, root.Execute()
	}

	t.Run("defaults", func(t *testing.T) {
		conf, err := execute(t)
		require.NoError(t, err)
		require.Equal(t, proposerconfig.Seed{GasLimit: 200_000_000, BuilderBoostFactor: 100}, conf.ProposerConfigSeed)
	})

	t.Run("flags parse", func(t *testing.T) {
		conf, err := execute(t,
			"--proposer-config-gas-limit=60000000",
			"--proposer-config-builder-urls=https://a.example.com",
			"--proposer-config-builder-min-bid=1",
			"--proposer-config-builder-boost-factor=90",
			"--proposer-config-builder-max-execution-payment=2",
		)
		require.NoError(t, err)
		require.Equal(t, proposerconfig.Seed{
			GasLimit:                   60_000_000,
			BuilderURLs:                []string{"https://a.example.com"},
			BuilderMinBid:              1,
			BuilderBoostFactor:         90,
			BuilderMaxExecutionPayment: 2,
			NonDefault: []string{
				"proposer-config-gas-limit", "proposer-config-builder-urls", "proposer-config-builder-min-bid",
				"proposer-config-builder-boost-factor", "proposer-config-builder-max-execution-payment",
			},
		}, conf.ProposerConfigSeed)
	})

	t.Run("builder value without urls", func(t *testing.T) {
		_, err := execute(t, "--proposer-config-builder-min-bid=1")
		require.ErrorContains(t, err, "require proposer-config-builder-urls")
	})

	t.Run("usage says the values are signed", func(t *testing.T) {
		cmd := newDKGCmd(nil)
		for _, flag := range []string{"proposer-config-gas-limit", "proposer-config-builder-urls", "proposer-config-builder-min-bid", "proposer-config-builder-boost-factor", "proposer-config-builder-max-execution-payment"} {
			usage := cmd.Flags().Lookup(flag).Usage
			require.Contains(t, usage, "Signed into the cluster's initial proposer config", flag)
			require.Contains(t, usage, "charon alpha edit proposer-config", flag)
			require.NotContains(t, usage, "disregarded", flag)
		}
	})

	t.Run("nickname still validated", func(t *testing.T) {
		_, err := execute(t, "--nickname="+strings.Repeat("a", 33))
		require.ErrorContains(t, err, "--nickname exceeds 32 character limit")
	})
}

func TestAddValidatorsProposerConfigFlags(t *testing.T) {
	var conf addValidatorsConfig

	root := newRootCmd(newAddValidatorsCmd(func(_ context.Context, config addValidatorsConfig) error {
		conf = config
		return nil
	}))

	root.SetArgs([]string{"add-validators"})
	require.NoError(t, root.Execute())
	require.Equal(t, ".charon/vc-config/proposer-config.json", conf.ProposerConfigFile)
	require.Equal(t, ".charon/builder_registrations_overrides.json", conf.OverridesFile)

	root.SetArgs([]string{"add-validators", "--proposer-config-file=pc.json", "--overrides-file=o.json"})
	require.NoError(t, root.Execute())
	require.Equal(t, "pc.json", conf.ProposerConfigFile)
	require.Equal(t, "o.json", conf.OverridesFile)
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

func TestFlagsToLogFieldsRedactsHeaders(t *testing.T) {
	set := pflag.NewFlagSet("test", pflag.PanicOnError)
	set.StringSlice("beacon-node-headers", nil, "")
	err := set.Parse([]string{
		"--beacon-node-headers=Authorization=Basic b2JvbDpzZWNyZXQ=",
	})
	require.NoError(t, err)

	for _, field := range flagsToLogFields(set) {
		field(func(f zap.Field) {
			if f.Key != "beacon-node-headers" {
				return
			}

			require.NotContains(t, f.String, "b2JvbDpzZWNyZXQ=")
			require.Contains(t, f.String, "Authorization=xxxxx")
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
			name:     "redact API keys in endpoint paths",
			flag:     "beacon-node-endpoints",
			value:    "https://eth-mainnet.example.com/v2/secret-key",
			expected: "https://eth-mainnet.example.com/xxxxx",
		},
		{
			name:     "redact query values in execution endpoints",
			flag:     "execution-client-rpc-endpoint",
			value:    "https://el.example.com?apikey=secret",
			expected: "https://el.example.com?apikey=xxxxx",
		},
		{
			name:     "keep local endpoints",
			flag:     "beacon-node-endpoints",
			value:    "http://lighthouse:5052",
			expected: "http://lighthouse:5052",
		},
		{
			name:     "redact builder URL passwords",
			flag:     "proposer-config-builder-urls",
			value:    "https://0xabc:secret@relay.example.com",
			expected: "https://0xabc:xxxxx@relay.example.com",
		},
		{
			name:     "no redact",
			flag:     "definition-file",
			value:    "https://obol.obol.tech/dv/0x0f481bbd06a596cb3ba569b9de0cbfcf822b209c2d6877c98173df986dd3c0ec",
			expected: "https://obol.obol.tech/dv/0x0f481bbd06a596cb3ba569b9de0cbfcf822b209c2d6877c98173df986dd3c0ec",
		},
		{
			name:     "redact beacon-node-headers value",
			flag:     "beacon-node-headers",
			value:    "Authorization=Basic b2JvbDpzZWNyZXQ=",
			expected: "Authorization=xxxxx",
		},
		{
			name:     "redact otlp-headers value",
			flag:     "otlp-headers",
			value:    "X-Api-Key=secret-api-key-12345",
			expected: "X-Api-Key=xxxxx",
		},
		{
			name:     "header without value passes through",
			flag:     "beacon-node-headers",
			value:    "X-No-Value",
			expected: "X-No-Value",
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
