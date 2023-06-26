// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package compose

import (
	"bytes"
	"context"
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

	const seed = 0
	keyGenFunc = func() (*k1.PrivateKey, error) {
		return testutil.GenerateInsecureK1Key(t, seed), nil
	}
	noPull = true

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			dir := t.TempDir()

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

	_, err = getVC(VCTeku, 0, 1, false, true)
	require.NoError(t, err)
}
