// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCmdFlags(t *testing.T) {
	tests := []struct {
		Name            string
		Args            []string
		VersionConfig   *VersionConfig
		BootstrapConfig *BootstrapConfig
	}{
		{
			Name:          "version verbose",
			Args:          slice("version", "--verbose"),
			VersionConfig: &VersionConfig{Verbose: true},
		}, {
			Name:          "version no verbose",
			Args:          slice("version", "--verbose=false"),
			VersionConfig: &VersionConfig{Verbose: false},
		},
		{
			Name: "bootstrap no flags",
			Args: slice("bootstrap"),
			BootstrapConfig: &BootstrapConfig{
				Out:          "./keys",
				Shares:       4,
				PasswordFile: "",
				Bootnodes:    nil,
			},
		},
		{
			Name: "bootstrap no flags",
			Args: slice("bootstrap", "-o=./gen_keys", "-n=6", "--password-file=./pass", `--bootnodes=hello,world`),
			BootstrapConfig: &BootstrapConfig{
				Out:          "./gen_keys",
				Shares:       6,
				PasswordFile: "./pass",
				Bootnodes:    []string{"hello", "world"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			root := newRoot(
				newVersionCmd(func(_ io.Writer, config VersionConfig) {
					require.NotNil(t, test.VersionConfig)
					require.Equal(t, *test.VersionConfig, config)
				}),
				newBootstrapCmd(func(_ io.Writer, config BootstrapConfig) error {
					require.NotNil(t, test.BootstrapConfig)
					require.Equal(t, *test.BootstrapConfig, config)
					return nil
				}),
			)

			root.SetArgs(test.Args)
			require.NoError(t, root.Execute())
		})
	}
}

// slice is a convenience function for creating string slice literals.
func slice(strs ...string) []string {
	return strs
}
