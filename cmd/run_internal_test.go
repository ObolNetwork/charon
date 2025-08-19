// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestBindPrivKeyFlag(t *testing.T) {
	tests := []struct {
		Name      string
		Args      []string
		AppConfig *app.Config
		Envs      map[string]string
		WantErr   bool
	}{
		{
			Name: "privKeyFile flag present/default and file exists",
			Args: slice("run"),
			Envs: map[string]string{
				"CHARON_BEACON_NODE_ENDPOINTS": "http://beacon.node",
			},
			AppConfig: &app.Config{
				PrivKeyFile: ".charon/charon-enr-private-key",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			root := newRootCmd(
				newRunCmd(func(_ context.Context, config app.Config) error {
					return nil
				}, false),
			)

			// Set envs (only for duration of the test)
			for k, v := range test.Envs {
				t.Setenv(k, v)
			}

			t.Cleanup(func() {
				for k := range test.Envs {
					require.NoError(t, os.Unsetenv(k))
				}
			})

			root.SetArgs(test.Args)

			if test.WantErr {
				require.Error(t, root.Execute())
			} else {
				_ = testutil.CreateTempCharonDir(t)
				_, err := p2p.NewSavedPrivKey(".charon/charon-enr-private-key")
				require.NoError(t, err)
				require.NoError(t, root.Execute())
			}
		})
	}
}

func TestBindRunFlagsValidation(t *testing.T) {
	tempDir := t.TempDir()
	certFile, err := os.CreateTemp(tempDir, "cert.pem")
	require.NoError(t, err)
	keyFile, err := os.CreateTemp(tempDir, "cert.key")
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, os.Remove(certFile.Name()))
		require.NoError(t, os.Remove(keyFile.Name()))
	})

	tests := []struct {
		Name      string
		Args      []string
		AppConfig *app.Config
		Err       string
	}{
		{
			Name: "minimum flags set",
			Args: slice("run", "--beacon-node-endpoints", "http://beacon.node"),
		},
		{
			Name: "too long nickname",
			Args: slice("run", "--beacon-node-endpoints", "http://beacon.node", "--nickname", "thisnicknameiswaytoolongandshouldfail"),
			Err:  "flag 'nickname' can not exceed 32 characters",
		},
		{
			Name: "valid nickname",
			Args: slice("run", "--beacon-node-endpoints", "http://beacon.node", "--nickname", "validnickname"),
		},
		{
			Name: "too long graffiti bytes",
			Args: slice("run", "--beacon-node-endpoints", "http://beacon.node", "--graffiti", "thisgraffitostringiswaytoolongandshouldfail"),
			Err:  "graffiti string length is greater than maximum size",
		},
		{
			Name: "valid graffiti bytes length",
			Args: slice("run", "--beacon-node-endpoints", "http://beacon.node", "--graffiti", "validgraffiti"),
		},
		{
			Name: "invalid beacon node headers separator",
			Args: slice("run", "--beacon-node-endpoints", "http://beacon.node", "--beacon-node-headers", "key1=value1,key2:value2"),
			Err:  "http headers must be comma separated values formatted as header=value",
		},
		{
			Name: "invalid beacon node headers completeness",
			Args: slice("run", "--beacon-node-endpoints", "http://beacon.node", "--beacon-node-headers", "key1=value1,key2="),
			Err:  "http headers must be comma separated values formatted as header=value",
		},
		{
			Name: "valid beacon node headers",
			Args: slice("run", "--beacon-node-endpoints", "http://beacon.node", "--beacon-node-headers", "key1=value1,key2=value2"),
		},
		{
			Name: "vc tls cert set without key",
			Args: slice("run", "--beacon-node-endpoints", "http://beacon.node", "--vc-tls-cert-file", "cert.pem"),
			Err:  "both vc-tls-cert-file and vc-tls-key-file must be set or both must be empty",
		},
		{
			Name: "vc tls key set without cert",
			Args: slice("run", "--beacon-node-endpoints", "http://beacon.node", "--vc-tls-key-file", "cert.key"),
			Err:  "both vc-tls-cert-file and vc-tls-key-file must be set or both must be empty",
		},
		{
			Name: "vc tls cert file does not exist",
			Args: slice("run", "--beacon-node-endpoints", "http://beacon.node", "--vc-tls-cert-file", "cert.pem", "--vc-tls-key-file", "cert.key"),
			Err:  "file vc-tls-cert-file does not exist",
		},
		{
			Name: "valid vc tls cert and key files",
			Args: slice("run", "--beacon-node-endpoints", "http://beacon.node", "--vc-tls-cert-file", certFile.Name(), "--vc-tls-key-file", keyFile.Name()),
		},
		{
			Name: "invalid hostname",
			Args: slice("run", "--beacon-node-endpoints", "http://beacon.node", "--p2p-external-hostname", "--p2p-tcp-address"),
			Err:  "invalid hostname",
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			root := newRootCmd(
				newRunCmd(func(_ context.Context, config app.Config) error {
					return nil
				}, false),
			)

			root.SetArgs(test.Args)

			if test.Err != "" {
				require.ErrorContains(t, root.Execute(), test.Err)
			} else {
				require.NoError(t, root.Execute())
			}
		})
	}
}
