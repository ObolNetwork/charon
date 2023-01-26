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

package compose

import (
	"bytes"
	"context"
	"math/rand"
	"os"
	"path"
	"testing"
	"text/template"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -update -clean

func TestDockerCompose(t *testing.T) {
	tests := []struct {
		Name     string
		ConfFunc func(*Config)
		RunFunc  func(ctx context.Context, dir string, conf Config) (TmplData, error)
	}{
		{
			Name: "define dkg",
			ConfFunc: func(conf *Config) {
				conf.KeyGen = KeyGenDKG
			},
			RunFunc: Define,
		},
		{
			Name: "define create",
			ConfFunc: func(conf *Config) {
				conf.KeyGen = KeyGenCreate
			},
			RunFunc: Define,
		},
		{
			Name: "lock dkg",
			ConfFunc: func(conf *Config) {
				conf.Step = stepDefined
				conf.KeyGen = KeyGenDKG
			},
			RunFunc: Lock,
		},
		{
			Name: "lock create",
			ConfFunc: func(conf *Config) {
				conf.Step = stepDefined
				conf.KeyGen = KeyGenCreate
			},
			RunFunc: Lock,
		},
		{
			Name: "run",
			ConfFunc: func(conf *Config) {
				conf.NumValidators = 2
				conf.Step = stepLocked
			},
			RunFunc: Run,
		},
	}

	random := rand.New(rand.NewSource(0))
	keyGenFunc = func() (*k1.PrivateKey, error) {
		return testutil.GenerateInsecureK1Key(t, random), nil
	}
	noPull = true

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "")
			require.NoError(t, err)

			conf := NewDefaultConfig()
			if test.ConfFunc != nil {
				test.ConfFunc(&conf)
			}
			data, err := test.RunFunc(context.Background(), dir, conf)
			require.NoError(t, err)

			t.Run("yml", func(t *testing.T) {
				b, err := os.ReadFile(path.Join(dir, "docker-compose.yml"))
				require.NoError(t, err)
				b = bytes.ReplaceAll(b, []byte(dir), []byte("testdir"))
				testutil.RequireGoldenBytes(t, b)
			})

			t.Run("template", func(t *testing.T) {
				data.ComposeDir = "testdir"
				testutil.RequireGoldenJSON(t, data)
			})
		})
	}
}

func TestParseTemplate(t *testing.T) {
	_, err := template.New("").Parse(string(tmpl))
	require.NoError(t, err)

	_, err = getVC(VCTeku, 0, 1, false)
	require.NoError(t, err)
}
