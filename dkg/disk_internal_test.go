// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
)

func TestLoadDefinition(t *testing.T) {
	// Valid definition
	lock, _, _ := cluster.NewForT(t, 1, 2, 3, 0)
	validDef := lock.Definition
	validFile := "valid-cluster-definition.json"
	b, err := json.MarshalIndent(validDef, "", " ")
	require.NoError(t, err)
	err = os.WriteFile(validFile, b, 0o666)
	require.NoError(t, err)

	// Invalid definition
	invalidDef := cluster.Definition{}
	invalidFile := "invalid-cluster-definition.json"
	err = os.WriteFile(invalidFile, []byte{1, 2, 3}, 0o666)
	require.NoError(t, err)

	// Invalid definition without definition_hash and config_hash
	invalidFile2 := "invalid-cluster-definition2.json"
	var rawJSONString map[string]any
	require.NoError(t, json.Unmarshal(b, &rawJSONString))

	delete(rawJSONString, "config_hash")
	delete(rawJSONString, "definition_hash")

	b2, err := json.Marshal(rawJSONString)
	require.NoError(t, err)

	err = os.WriteFile(invalidFile2, b2, 0o666)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, os.Remove(validFile))
		require.NoError(t, os.Remove(invalidFile))
		require.NoError(t, os.Remove(invalidFile2))
	}()

	tests := []struct {
		name     string
		defFile  string
		want     cluster.Definition
		noVerify bool
		wantErr  bool
	}{
		{
			name:     "Load valid definition",
			defFile:  validFile,
			want:     validDef,
			noVerify: false,
			wantErr:  false,
		},
		{
			name:     "Definition file doesn't exist",
			defFile:  "",
			want:     invalidDef,
			noVerify: false,
			wantErr:  true,
		},
		{
			name:     "Load invalid definition",
			defFile:  invalidFile,
			want:     invalidDef,
			noVerify: false,
			wantErr:  true,
		},
		{
			name:     "Load invalid definition with no verify",
			defFile:  invalidFile2,
			want:     validDef,
			noVerify: true,
			wantErr:  false,
		},
		{
			name:     "Load invalid definition without no verify",
			defFile:  invalidFile2,
			noVerify: false,
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := loadDefinition(context.Background(), Config{DefFile: tt.defFile, NoVerify: tt.noVerify})
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			got, err = got.SetDefinitionHashes()
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
