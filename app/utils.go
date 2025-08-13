// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"archive/tar"
	"bytes"
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

// ExtractArchive extracts a .tar.gz archive to the target directory.
func ExtractArchive(archivePath, targetDir string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return errors.Wrap(err, "open archive file")
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return errors.Wrap(err, "create gzip reader")
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			return nil // End of archive
		}

		if err != nil {
			return errors.Wrap(err, "tar read error")
		}

		target := filepath.Join(targetDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, header.FileInfo().Mode()); err != nil {
				return errors.Wrap(err, "create directory")
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return errors.Wrap(err, "create parent directory")
			}

			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, header.FileInfo().Mode())
			if err != nil {
				return errors.Wrap(err, "create file")
			}

			_, err = io.Copy(f, tr)
			if err != nil {
				f.Close()
				return errors.Wrap(err, "copy file contents")
			}

			if err := f.Close(); err != nil {
				return errors.Wrap(err, "close file")
			}
		default:
			// Skip other types (symlinks, etc.)
		}
	}
}

// CompareDirectories recursively compares two directories and their contents.
func CompareDirectories(originalDir, extractedDir string) error {
	return filepath.Walk(originalDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(originalDir, path)
		if err != nil {
			return errors.Wrap(err, "get relative path")
		}

		extractedPath := filepath.Join(extractedDir, relPath)

		if info.IsDir() {
			// Check if directory exists in extracted content
			extractedInfo, err := os.Stat(extractedPath)
			if err != nil {
				return errors.Wrap(err, "directory should exist in extracted content", z.Str("path", relPath))
			}

			if !extractedInfo.IsDir() {
				return errors.New("should be a directory", z.Str("path", relPath))
			}

			return nil
		}

		// Compare file contents
		extractedInfo, err := os.Stat(extractedPath)
		if err != nil {
			return errors.Wrap(err, "file should exist in extracted content", z.Str("path", relPath))
		}

		if info.Size() != extractedInfo.Size() {
			return errors.New("file sizes should match", z.Str("path", relPath))
		}

		// Read and compare file contents
		originalContent, err := os.ReadFile(path)
		if err != nil {
			return errors.Wrap(err, "read original file", z.Str("path", path))
		}

		extractedContent, err := os.ReadFile(extractedPath)
		if err != nil {
			return errors.Wrap(err, "read extracted file", z.Str("path", extractedPath))
		}

		if !bytes.Equal(originalContent, extractedContent) {
			return errors.New("file contents should match", z.Str("path", relPath))
		}

		return nil
	})
}
