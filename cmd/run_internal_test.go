// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/p2p"
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
				require.NoError(t, os.Setenv(k, v))
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
				require.NoError(t, os.Mkdir(".charon", 0o755))
				defer func() {
					require.NoError(t, os.RemoveAll(".charon"))
				}()

				_, err := p2p.NewSavedPrivKey(".charon/charon-enr-private-key")
				require.NoError(t, err)
				require.NoError(t, root.Execute())
			}
		})
	}
}
