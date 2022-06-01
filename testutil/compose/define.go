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
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

// zeroXDead is the 0x00..00dead Ethereum address.
const zeroXDead = `"0x000000000000000000000000000000000000dead"`

// Clean deletes all compose directory files and artifacts.
func Clean(ctx context.Context, dir string) error {
	ctx = log.WithTopic(ctx, "clean")

	files, err := filepath.Glob(path.Join(dir, "*"))
	if err != nil {
		return errors.Wrap(err, "glob dir")
	}

	// Make sure we ONLY delete compose artifacts.
	var (
		configFound bool
		goFound     bool
	)
	for _, file := range files {
		if file == configFile {
			configFound = true
		} else if strings.HasSuffix(file, ".go") || strings.HasPrefix(file, "go.") {
			goFound = true
		}
	}
	if !configFound {
		log.Info(ctx, "Not cleaning since config.json not found")
		return nil
	} else if goFound {
		return errors.New("go files found, compose dir incorrect", z.Str("dir", dir))
	}

	log.Info(ctx, "Cleaning compose dir", z.Int("files", len(files)))

	for _, file := range files {
		if strings.Contains(file, "key") {
			// Do not delete root folder with key in the name, since it might be long-lived split keys folder.
			log.Info(ctx, "Not deleting *key* folder", z.Str("path", file))
			continue
		}
		if err := os.RemoveAll(file); err != nil {
			return errors.Wrap(err, "remove file")
		}
	}

	return nil
}

// noPull allows disabling pulling during unit tests.
var noPull bool

// Define defines a compose cluster; including both keygen and running definitions.
func Define(ctx context.Context, dir string, conf Config) (TmplData, error) {
	if conf.Step != stepNew {
		return TmplData{}, errors.New("compose config not new, so can't be defined", z.Any("step", conf.Step))
	}

	if conf.BuildBinary {
		if err := buildLocal(ctx, dir); err != nil {
			return TmplData{}, err
		}
	}

	if !noPull && !conf.BuildBinary && !conf.PrebuiltBinary && conf.ImageTag == "latest" {
		if err := pullLatest(ctx); err != nil {
			return TmplData{}, err
		}
	}

	if conf.SplitKeysDir != "" {
		if err := validateSplitKeysDir(dir, conf.SplitKeysDir); err != nil {
			return TmplData{}, err
		}
	}

	var data TmplData
	if conf.KeyGen == KeyGenDKG {
		log.Info(ctx, "Creating node*/p2pkey for ENRs required for charon create dkg")

		// charon create dkg requires operator ENRs, so we need to create p2pkeys now.
		p2pkeys, err := newP2PKeys(conf.NumNodes)
		if err != nil {
			return TmplData{}, err
		}

		var enrs []string
		for i, key := range p2pkeys {
			// Best effort creation of folder, rather fail when saving p2pkey file next.
			_ = os.MkdirAll(nodeFile(dir, i, ""), 0o755)

			err := crypto.SaveECDSA(nodeFile(dir, i, "p2pkey"), key)
			if err != nil {
				return TmplData{}, errors.Wrap(err, "save p2pkey")
			}

			enrStr, err := keyToENR(key)
			if err != nil {
				return TmplData{}, err
			}
			enrs = append(enrs, enrStr)
		}

		n := node{EnvVars: []kv{
			{"name", "compose"},
			{"num_validators", fmt.Sprint(conf.NumValidators)},
			{"operator_enrs", strings.Join(enrs, ",")},
			{"threshold", fmt.Sprint(conf.Threshold)},
			{"withdrawal_address", zeroXDead},
			{"dkg_algorithm", "frost"},
			{"output_dir", "/compose"},
		}}

		data = TmplData{
			ComposeDir:       dir,
			CharonImageTag:   conf.ImageTag,
			CharonEntrypoint: conf.entrypoint(),
			CharonCommand:    cmdCreateDKG,
			Nodes:            []node{n},
		}
	} else {
		// Other keygens only need a noop docker-compose, since charon-compose.yml
		// is used directly in their compose lock.

		data = TmplData{
			ComposeDir:       dir,
			CharonImageTag:   conf.ImageTag,
			CharonEntrypoint: "echo",
			CharonCommand:    fmt.Sprintf("No charon commands needed for keygen=%s define step", conf.KeyGen),
			Nodes:            []node{{}},
		}
	}

	log.Info(ctx, "Creating config.json")

	conf.Step = stepDefined
	if err := WriteConfig(dir, conf); err != nil {
		return TmplData{}, err
	}

	if err := copyStaticFolders(dir); err != nil {
		return TmplData{}, err
	}

	log.Info(ctx, "Creating docker-compose.yml")
	log.Info(ctx, "Create cluster definition: docker-compose up")

	if err := WriteDockerCompose(dir, data); err != nil {
		return TmplData{}, err
	}

	return data, nil
}

// validateSplitKeysDir returns an error if the split keys dir is not a child of dir.
func validateSplitKeysDir(dir string, spitKeysDir string) error {
	rel, err := getRelSplitKeysDir(dir, spitKeysDir)
	if err != nil {
		return err
	} else if strings.HasPrefix(rel, "..") {
		return errors.New("split-keys-dir must be a child of compose dir", z.Str("relative", rel))
	}

	return nil
}

// getRelSplitKeysDir returns the splitKeysDir as a relative path to dir.
func getRelSplitKeysDir(dir, splitKeysDir string) (string, error) {
	if splitKeysDir == "" {
		return "", nil
	}

	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", errors.Wrap(err, "abs dir")
	}
	splitKeysDir, err = filepath.Abs(splitKeysDir)
	if err != nil {
		return "", errors.Wrap(err, "abs dir")
	}

	rel, err := filepath.Rel(dir, splitKeysDir)
	if err != nil {
		return "", errors.Wrap(err, "relative split keys dir")
	}

	return rel, nil
}

// pullLatest pulls the latest charon docker image.
func pullLatest(ctx context.Context) error {
	log.Info(ctx, "Pulling latest charon docker image")

	cmd := exec.CommandContext(ctx, "docker", "pull", charonImage+":latest")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return errors.Wrap(err, "run docker pull")
	}

	return nil
}

// buildLocal builds a local charon binary and writes it to the cluster dir. Note this requires CHARON_REPO env var.
func buildLocal(ctx context.Context, dir string) error {
	repo, ok := os.LookupEnv("CHARON_REPO")
	if !ok || repo == "" {
		return errors.New("cannot build local charon binary; CHARON_REPO env var, the path to the charon repo, is not set")
	}

	dir, err := filepath.Abs(dir)
	if err != nil {
		return errors.Wrap(err, "abs dir")
	}

	target := path.Join(dir, "charon")

	log.Info(ctx, "Building local charon binary", z.Str("repo", repo), z.Str("target", target))

	cmd := exec.CommandContext(ctx, "go", "build", "-o", target)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = repo

	if err := cmd.Run(); err != nil {
		return errors.Wrap(err, "exec go build")
	}

	return nil
}

// copyStaticFolders copies the embedded static folders to the compose dir.
func copyStaticFolders(dir string) error {
	const staticRoot = "static"
	dirs, err := static.ReadDir(staticRoot)
	if err != nil {
		return errors.Wrap(err, "read dirs")
	}
	for _, d := range dirs {
		if !d.IsDir() {
			return errors.New("static files not supported")
		}

		if err := os.MkdirAll(path.Join(dir, d.Name()), 0o755); err != nil {
			return errors.Wrap(err, "mkdir all")
		}

		files, err := static.ReadDir(path.Join(staticRoot, d.Name()))
		if err != nil {
			return errors.Wrap(err, "read files")
		}

		for _, f := range files {
			if f.IsDir() {
				return errors.New("child static dirs not supported")
			}

			b, err := static.ReadFile(path.Join(staticRoot, d.Name(), f.Name()))
			if err != nil {
				return errors.Wrap(err, "read file")
			}

			var mode os.FileMode = 0o644
			if strings.HasSuffix(f.Name(), ".sh") {
				mode = 0o755
			}

			if err := os.WriteFile(path.Join(dir, d.Name(), f.Name()), b, mode); err != nil {
				return errors.Wrap(err, "write file")
			}
		}
	}

	return nil
}

func keyToENR(key *ecdsa.PrivateKey) (string, error) {
	var r enr.Record
	r.SetSeq(0)

	err := enode.SignV4(&r, key)
	if err != nil {
		return "", errors.Wrap(err, "sign enr")
	}

	return p2p.EncodeENR(r)
}

// p2pSeed can be overridden in tests for deterministic p2pkeys.
var p2pSeed = time.Now().UnixNano()

// newP2PKeys returns a slice of newly generated ecdsa private keys.
func newP2PKeys(n int) ([]*ecdsa.PrivateKey, error) {
	random := rand.New(rand.NewSource(p2pSeed)) //nolint:gosec // Weak random is fine for testing.
	var resp []*ecdsa.PrivateKey
	for i := 0; i < n; i++ {
		key, err := ecdsa.GenerateKey(crypto.S256(), random)
		if err != nil {
			return nil, errors.Wrap(err, "new key")
		}
		resp = append(resp, key)
	}

	return resp, nil
}

// nodeFile returns the path to a file in a node folder.
func nodeFile(dir string, i int, file string) string {
	return path.Join(dir, fmt.Sprintf("node%d", i), file)
}

// WriteConfig writes the config as yaml to disk.
func WriteConfig(dir string, conf Config) error {
	b, err := json.MarshalIndent(conf, "", " ")
	if err != nil {
		return errors.Wrap(err, "marshal config")
	}

	err = os.WriteFile(path.Join(dir, configFile), b, 0o755) //nolint:gosec
	if err != nil {
		return errors.Wrap(err, "write config")
	}

	return nil
}
