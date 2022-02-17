// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command fork extracts a fresh fork of github.com/consensys/quorum/consensus/istanbul/qbft/core
// into the goquorum package. It provides a programmatic way to keep our qbft fork up to date
// with the upstream.
package main

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	err := run(ctx)
	if err != nil {
		log.Error(ctx, "failure", err)
	}
}

func run(ctx context.Context) error {
	// Ensure we are in this pull dir
	out, err := execute(ctx, "", "stat", "pull.go")
	if err != nil {
		return errors.Wrap(err, "not in pull directory", z.Str("out", string(out)))
	}

	workDir := "tmp"
	defer func() {
		_ = os.RemoveAll(workDir)
	}()

	if err := checkout(ctx, workDir); err != nil {
		return err
	}

	// Extract istanbul consensus from repo.
	out, err = execute(ctx, workDir, "cp",
		"-R",
		"quorum/consensus/istanbul",
		"istanbul")
	if err != nil {
		return errors.Wrap(err, "cp istanbul", z.Str("out", string(out)))
	}

	// pkgToDir is a function that maps a go package to a dir.
	pkgToDir := func(pkg string) string {
		return strings.ReplaceAll(pkg, "github.com/ethereum/go-ethereum/consensus", workDir)
	}

	// find all imports of istanbul/qbft/core
	imprts, err := findImports(ctx,
		"github.com/ethereum/go-ethereum/consensus/istanbul/qbft/core",
		"github.com/ethereum/go-ethereum/consensus/istanbul",
		pkgToDir,
	)
	if err != nil {
		return err
	}

	// delete all other packages under instanbul.
	err = deleteUnusedPkgs("github.com/ethereum/go-ethereum/consensus/istanbul", imprts, pkgToDir)
	if err != nil {
		return err
	}

	// Rename imports from go-ethereum to charon.
	out, err = execute(ctx, workDir, "find", "istanbul/", "-name", "*.go", "-exec", "sed", "-i", "",
		"s#github.com/ethereum/go-ethereum/consensus/istanbul#github.com/obolnetwork/charon/goquorum/istanbul#g", "{}", "+")
	if err != nil {
		return errors.Wrap(err, "find sed", z.Str("out", string(out)))
	}

	// TODO(corver): Add a istanbul.RawProposal type and replace reference to types.Block.

	// Move result from work dir to target dir.
	out, err = execute(ctx, workDir, "mv", "istanbul", "../../istanbul")
	if err != nil {
		return errors.Wrap(err, "cp istanbul", z.Str("out", string(out)))
	}

	return nil
}

// deleteUnusedPkgs deletes all packages (and sub-packages) from basePkg that are not referenced by the imports.
func deleteUnusedPkgs(basePkg string, imprts map[string]bool, pkgToDir func(pkg string) string) error {
	var inImports bool
	for imprt := range imprts {
		if strings.HasPrefix(imprt, basePkg) {
			inImports = true
			break
		}
	}

	dir := pkgToDir(basePkg)
	if !inImports {
		return removeAll(dir)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return errors.Wrap(err, "read dir")
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		err := deleteUnusedPkgs(path.Join(basePkg, entry.Name()), imprts, pkgToDir)
		if err != nil {
			return err
		}
	}

	return nil
}

// findImports recursively finds all imports marching the prefix from a package and returns the unique set.
func findImports(ctx context.Context, fromPkg string, importPrefix string,
	pkgToDir func(string) string) (map[string]bool, error,
) {
	out, err := execute(ctx, pkgToDir(fromPkg), "go", "list", "-f",
		"{{range $imp := .Imports}}{{printf \"%s\\n\" $imp}}{{end}}")
	if err != nil {
		return nil, err
	}

	imprts := make(map[string]bool)

	if strings.HasPrefix(fromPkg, importPrefix) {
		imprts[fromPkg] = true
	}

	for _, imprt := range strings.Split(string(out), "\n") {
		imprt = strings.TrimSpace(imprt)
		if !strings.HasPrefix(imprt, importPrefix) {
			continue
		}
		imprts[imprt] = true

		nexts, err := findImports(ctx, imprt, importPrefix, pkgToDir)
		if err != nil {
			return nil, err
		}

		for imprt := range nexts {
			imprts[imprt] = true
		}
	}

	return imprts, nil
}

// checkout checks out a shallow copy of github.com:ConsenSys/quorum.git into workdir.
func checkout(ctx context.Context, workDir string) error {
	_ = os.RemoveAll(workDir)

	err := os.Mkdir(workDir, 0o755)
	if err != nil {
		return errors.Wrap(err, "mkdir")
	}

	out, err := execute(ctx, workDir, "git",
		"clone",
		"--depth=1",
		"git@github.com:ConsenSys/quorum.git")
	if err != nil {
		return errors.Wrap(err, "git clone", z.Str("out", string(out)))
	}

	return nil
}

// execute runs a command from dir and returns the output or a wrapped error.
func execute(ctx context.Context, dir string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, errors.Wrap(err, "exec")
	}

	return out, nil
}

// removeAll removes path p and any children it contains and wraps the error.
func removeAll(p string) error {
	err := os.RemoveAll(p)
	if err != nil {
		return errors.Wrap(err, "remove")
	}

	return nil
}
