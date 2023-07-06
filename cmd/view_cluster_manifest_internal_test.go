// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
)

func Test_viewClusterManifest(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 1, 4, 4, 1)

	lockMutation, err := manifest.NewLegacyLock(lock)
	require.NoError(t, err)

	cluster, err := manifest.Materialise(&manifestpb.SignedMutationList{Mutations: []*manifestpb.SignedMutation{lockMutation}})
	require.NoError(t, err)

	clusterBytes, err := proto.Marshal(cluster)
	require.NoError(t, err)

	clusterPath := filepath.Join(t.TempDir(), "cluster-manifest.pb")

	require.NoError(t, os.WriteFile(clusterPath, clusterBytes, 0o655))

	var output bytes.Buffer
	require.NoError(t, viewClusterManifest(clusterPath, &output))

	require.NotEmpty(t, output.Bytes())

	outputMap := make(map[string]any)

	require.NoError(t, json.Unmarshal(output.Bytes(), &outputMap))
}
