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

package main

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil/compose"
)

//go:generate go test . -run=TestSmoke -integration
var integration = flag.Bool("integration", false, "Enable docker based integration test")

func TestSmoke(t *testing.T) {
	if !*integration {
		t.Skip("Skipping smoke integration test")
	}

	tests := []struct {
		Name       string
		ConfigFunc func(*compose.Config)
		TmplFunc   func(compose.TmplData)
	}{
		{
			Name: "default alpha flow",
			ConfigFunc: func(conf *compose.Config) {
				conf.FeatureSet = "alpha"
			},
		},
		{
			Name: "default beta flow",
			ConfigFunc: func(conf *compose.Config) {
				conf.FeatureSet = "beta"
			},
		},
		{
			Name: "default stable flow",
			ConfigFunc: func(conf *compose.Config) {
				conf.FeatureSet = "stable"
			},
		},
		{
			Name: "dkg flow",
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = "dkg"
			},
		},
		{
			Name: "version matrix",
			TmplFunc: func(data compose.TmplData) {
				data.Nodes[0].ImageTag = "latest"
				data.Nodes[1].ImageTag = "v0.5.0"
				data.Nodes[2].ImageTag = "v0.4.0"
				data.Nodes[3].ImageTag = "v0.3.0"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "")
			require.NoError(t, err)

			conf := compose.NewDefaultConfig()
			if test.ConfigFunc != nil {
				test.ConfigFunc(&conf)
			}
			require.NoError(t, compose.WriteConfig(dir, conf))

			cmd := newAutoCmd(test.TmplFunc)
			require.NoError(t, cmd.Flags().Set("compose-dir", dir))
			require.NoError(t, cmd.Flags().Set("alert-timeout", "1m"))

			err = cmd.ExecuteContext(context.Background())
			require.NoError(t, err)
		})
	}
}
