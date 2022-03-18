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

package app

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path"
	"strings"

	"github.com/dB2510/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

const (
	simnetKeysFile = "simnetkeys"
)

// loadManifest reads the cluster manifest from the given file path.
func loadManifest(conf Config) (Manifest, error) {
	if conf.TestConfig.Manifest != nil {
		return *conf.TestConfig.Manifest, nil
	}

	buf, err := os.ReadFile(conf.ManifestFile)
	if err != nil {
		return Manifest{}, errors.Wrap(err, "read manifest")
	}

	var res Manifest
	err = json.Unmarshal(buf, &res)
	if err != nil {
		return Manifest{}, errors.Wrap(err, "unmarshal manifest")
	}

	return res, nil
}

// loadSimnetKeys returns the keys from the file in the data directory.
func loadSimnetKeys(conf Config) ([]*bls_sig.SecretKey, error) {
	if len(conf.TestConfig.SimnetKeys) != 0 {
		return conf.TestConfig.SimnetKeys, nil
	}

	content, err := os.ReadFile(path.Join(conf.DataDir, simnetKeysFile))
	if err != nil {
		return nil, errors.Wrap(err, "read simnetkeys")
	}

	var resp []*bls_sig.SecretKey
	for _, line := range strings.Split(string(content), "\n") {
		b, err := hex.DecodeString(line)
		if err != nil {
			return nil, errors.Wrap(err, "decode hex")
		}

		secret, err := tblsconv.SecretFromBytes(b)
		if err != nil {
			return nil, errors.Wrap(err, "read simnetkeys")
		}

		resp = append(resp, secret)
	}

	return resp, nil
}

// StoreSimnetKeys stores the keys as a hex new line delimited file in the directory.
func StoreSimnetKeys(keys []*bls_sig.SecretKey, dir string) error {
	var hexKeys []string
	for _, key := range keys {
		b, err := tblsconv.SecretToBytes(key)
		if err != nil {
			return err
		}

		hexKeys = append(hexKeys, hex.EncodeToString(b))
	}

	content := []byte(strings.Join(hexKeys, "\n"))

	secretsPath := path.Join(dir, simnetKeysFile)
	if err := os.WriteFile(secretsPath, content, 0o600); err != nil {
		return errors.Wrap(err, "write simnet keys")
	}

	return nil
}
