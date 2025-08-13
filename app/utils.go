// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"archive/tar"
	"compress/gzip"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

// Hex7 returns the first 7 (or less) hex chars of the provided bytes.
func Hex7(input []byte) string {
	resp := hex.EncodeToString(input)
	if len(resp) <= 7 {
		return resp
	}

	return resp[:7]
}

// BundleOutput archives targetDir into a gzipped tarball named filename in targetDir.
// After successfully creating the archive, it deletes the original files from disk.
func BundleOutput(targetDir string, filename string) error {
	// Create output file
	file, err := os.Create(filepath.Join(targetDir, filename))
	if err != nil {
		return errors.Wrap(err, "create .tar.gz file")
	}
	defer file.Close()

	gzw := gzip.NewWriter(file)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	// Files to be deleted
	dirsToDelete := make([]string, 0)
	filesToDelete := make([]string, 0)

	// Walk the target directory
	err = filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return errors.Wrap(err, "filepath walk")
		}

		if !info.Mode().IsRegular() {
			// Don't delete target directory
			if info.IsDir() && path != targetDir {
				dirsToDelete = append(dirsToDelete, path)
			}

			return nil
		}

		// Don't delete output file
		if path == file.Name() {
			return nil
		}

		relPath, err := filepath.Rel(targetDir, path)
		if err != nil {
			return errors.Wrap(err, "relative path")
		}

		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			return errors.Wrap(err, "file info header")
		}

		header.Name = relPath
		if err := tw.WriteHeader(header); err != nil {
			return errors.Wrap(err, "write header")
		}

		f, err := os.Open(path)
		if err != nil {
			return errors.Wrap(err, "open file")
		}
		defer f.Close()

		_, err = io.Copy(tw, f)
		if err != nil {
			return errors.Wrap(err, "copy file", z.Str("filename", path))
		}

		filesToDelete = append(filesToDelete, path)

		return nil
	})
	if err != nil {
		return errors.Wrap(err, "filepath walk")
	}

	// Delete files/folders
	for _, path := range filesToDelete {
		err := os.RemoveAll(path)
		if err != nil {
			return errors.Wrap(err, "remove file", z.Str("filename", path))
		}
	}

	for _, path := range dirsToDelete {
		err := os.RemoveAll(path)
		if err != nil {
			return errors.Wrap(err, "remove dir", z.Str("filename", path))
		}
	}

	return nil
}
