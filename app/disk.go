// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"io"
	"os"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth1wrap"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
)

// loadClusterLock loads and verifies the cluster lock.
func loadClusterLock(ctx context.Context, conf Config, eth1Cl eth1wrap.EthClientRunner) (*cluster.Lock, error) {
	if conf.TestConfig.Lock != nil {
		return conf.TestConfig.Lock, nil
	}

	return cluster.LoadClusterLock(ctx, conf.LockFile, conf.NoVerify, eth1Cl)
}

// FileExists checks if a file exists at the given path.
func FileExists(path string) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}

	return err == nil
}

// CreateNewEmptyDir creates a new directory that must be empty.
// If the directory already exists and is not empty, it returns an error.
func CreateNewEmptyDir(dir string) error {
	err := os.Mkdir(dir, os.ModePerm)
	if err == nil {
		return nil
	}

	if !os.IsExist(err) {
		return errors.Wrap(err, "mkdir", z.Str("path", dir))
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		return errors.Wrap(err, "readdir", z.Str("path", dir))
	}

	if len(files) == 0 {
		return nil
	}

	return errors.New("directory not empty", z.Str("path", dir))
}

// CopyFile copies a file from src to dst. If dst already exists, it will be overwritten.
func CopyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return errors.Wrap(err, "open source file", z.Str("file", src))
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(dst)
	if err != nil {
		return errors.Wrap(err, "create destination file", z.Str("file", dst))
	}
	defer destinationFile.Close()

	_, err = io.Copy(destinationFile, sourceFile)
	if err != nil {
		return errors.Wrap(err, "copy file content", z.Str("src", src), z.Str("dst", dst))
	}

	// Sync the destination file to ensure data is flushed to disk.
	// This can be important for data integrity, especially on systems with caching.
	err = destinationFile.Sync()
	if err != nil {
		return errors.Wrap(err, "sync destination file", z.Str("file", dst))
	}

	sourceInfo, err := os.Stat(src)
	if err != nil {
		return errors.Wrap(err, "get source file info", z.Str("file", src))
	}

	err = os.Chmod(dst, sourceInfo.Mode().Perm())
	if err != nil {
		return errors.Wrap(err, "set destination file permissions", z.Str("file", dst))
	}

	return nil
}
