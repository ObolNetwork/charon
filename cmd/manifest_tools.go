// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"fmt"
	"os"
	"path"

	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
)

// loadClusterManifest loads cluster manifest from disk.
func loadClusterManifest(manifestFilePath, lockFilePath string) (*manifestpb.Cluster, error) {
	verifyLock := func(lock cluster.Lock) error {
		if err := lock.VerifyHashes(); err != nil {
			return errors.Wrap(err, "cluster lock hash verification failed")
		}

		if err := lock.VerifySignatures(); err != nil {
			return errors.Wrap(err, "cluster lock signature verification failed")
		}

		return nil
	}

	cluster, err := manifest.LoadCluster(manifestFilePath, lockFilePath, verifyLock)
	if err != nil {
		return nil, errors.Wrap(err, "load cluster manifest from disk")
	}

	return cluster, nil
}

// loadDAGFromDisk loads cluster DAG from disk.
func loadDAGFromDisk(manifestFilePath, lockFilePath string) (*manifestpb.SignedMutationList, error) {
	verifyLock := func(lock cluster.Lock) error {
		if err := lock.VerifyHashes(); err != nil {
			return errors.Wrap(err, "cluster lock hash verification failed")
		}

		if err := lock.VerifySignatures(); err != nil {
			return errors.Wrap(err, "cluster lock signature verification failed")
		}

		return nil
	}

	dag, err := manifest.LoadDAG(manifestFilePath, lockFilePath, verifyLock)
	if err != nil {
		return nil, errors.Wrap(err, "load cluster dag from disk")
	}

	return dag, nil
}

// writeCluster writes the provided cluster DAG as manifest file to node directories on disk.
func writeCluster(clusterDir string, numOps int, dag *manifestpb.SignedMutationList) error {
	b, err := proto.Marshal(dag)
	if err != nil {
		return errors.Wrap(err, "proto marshal dag")
	}

	// Write cluster manifest to node directories on disk
	for i := 0; i < numOps; i++ {
		dir := path.Join(clusterDir, fmt.Sprintf("node%d", i))
		filename := path.Join(dir, "cluster-manifest.pb")
		//nolint:gosec // File needs to be read-write since the cluster manifest is modified by mutations.
		err = os.WriteFile(filename, b, 0o644) // Read-write
		if err != nil {
			return errors.Wrap(err, "write cluster manifest")
		}
	}

	return nil
}
