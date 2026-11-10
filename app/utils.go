// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"archive/tar"
	"compress/gzip"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

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
// The archive contains private key material, so it is only readable and writable by its owner.
// It is written to a temporary file and renamed into place once complete, so filename is
// never a partial archive. The original files are deleted only once the archive is in place,
// so a failure before that leaves them untouched.
func BundleOutput(targetDir string, filename string) (err error) {
	archivePath := filepath.Join(targetDir, filename)
	tempPrefix := filename + ".tmp-"

	// CreateTemp creates the tempFile with mode 0600.
	tempFile, err := os.CreateTemp(targetDir, tempPrefix+"*")
	if err != nil {
		return errors.Wrap(err, "create .tar.gz file")
	}

	// CreateTemp does not clean its path while filepath.Walk does, e.g. for the default "./" directory.
	tempPath := filepath.Clean(tempFile.Name())

	defer func() {
		if err != nil {
			_ = tempFile.Close()
			_ = os.Remove(tempFile.Name())
		}
	}()

	gzw := gzip.NewWriter(tempFile)
	tw := tar.NewWriter(gzw)

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

		// Don't archive or delete the output file, nor an archive left by a previous run (it is replaced).
		if path == tempPath || path == archivePath {
			return nil
		}

		// Don't archive a temporary file left by an interrupted run, but do delete it.
		if strings.HasPrefix(info.Name(), tempPrefix) {
			filesToDelete = append(filesToDelete, path)

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

		f, err := os.Open(path) //nolint:gosec // no TOCTOU condition as BundleOutput is used only in CLI non-concurrent context.
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

	// Flush the archive to disk and move it into place before deleting the originals,
	// so a failed write never loses them.
	if err := tw.Close(); err != nil {
		return errors.Wrap(err, "close tar writer")
	}

	if err := gzw.Close(); err != nil {
		return errors.Wrap(err, "close gzip writer")
	}

	if err := tempFile.Sync(); err != nil {
		return errors.Wrap(err, "sync .tar.gz file")
	}

	if err := tempFile.Close(); err != nil {
		return errors.Wrap(err, "close .tar.gz file")
	}

	if err := os.Rename(tempFile.Name(), archivePath); err != nil {
		return errors.Wrap(err, "rename .tar.gz file")
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
