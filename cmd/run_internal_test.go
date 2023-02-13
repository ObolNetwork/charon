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
				}),
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
