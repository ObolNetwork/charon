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
	"encoding/json"
	"fmt"
	"os"
	"path"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// Lock creates a docker-compose.yml from a charon-compose.yml for generating keys and a cluster lock file.
func Lock(ctx context.Context, dir string, conf Config) (TmplData, error) {
	if conf.Step != stepDefined {
		return TmplData{}, errors.New("compose config not defined, so can't be locked", z.Any("step", conf.Step))
	}

	var data TmplData
	switch conf.KeyGen {
	case KeyGenCreate:
		splitKeysDir, err := getRelSplitKeysDir(dir, conf.SplitKeysDir)
		if err != nil {
			return TmplData{}, err
		} else if splitKeysDir != "" {
			splitKeysDir = path.Join("/compose", splitKeysDir)
		}

		// Only single node to call charon create cluster generate keys
		n := node{EnvVars: []kv{
			{"threshold", fmt.Sprint(conf.Threshold)},
			{"nodes", fmt.Sprint(conf.NumNodes)},
			{"cluster-dir", "/compose"},
			{"split-existing-keys", fmt.Sprintf(`"%v"`, conf.SplitKeysDir != "")},
			{"split-keys-dir", splitKeysDir},
		}}

		data = TmplData{
			ComposeDir:       dir,
			CharonImageTag:   conf.ImageTag,
			CharonEntrypoint: conf.entrypoint(),
			CharonCommand:    cmdCreateCluster,
			Nodes:            []node{n},
		}
	case KeyGenDKG:

		var nodes []node
		for i := 0; i < conf.NumNodes; i++ {
			n := node{EnvVars: newNodeEnvs(i, true, conf)}
			nodes = append(nodes, n)
		}

		data = TmplData{
			ComposeDir:       dir,
			CharonImageTag:   conf.ImageTag,
			CharonEntrypoint: conf.entrypoint(),
			CharonCommand:    cmdDKG,
			Bootnode:         true,
			Nodes:            nodes,
		}
	default:
		return TmplData{}, errors.New("supported keygen")
	}

	log.Info(ctx, "Creating docker-compose.yml")
	log.Info(ctx, "Create keys and cluster lock with: docker-compose up")

	conf.Step = stepLocked
	if err := WriteConfig(dir, conf); err != nil {
		return TmplData{}, err
	}

	if err := WriteDockerCompose(dir, data); err != nil {
		return TmplData{}, err
	}

	return data, nil
}

// newNodeEnvs returns the default node environment variable to run a charon docker container.
func newNodeEnvs(index int, validatorMock bool, conf Config) []kv {
	beaconMock := false
	beaconNode := conf.BeaconNode
	if beaconNode == "mock" {
		beaconMock = true
		beaconNode = ""
	}

	lockFile := "/compose/cluster-lock.json"
	if conf.KeyGen == KeyGenDKG {
		// Lock files for DKG in node dirs.
		lockFile = fmt.Sprintf("/compose/node%d/cluster-lock.json", index)
	}

	return []kv{
		{"data-dir", fmt.Sprintf("/compose/node%d", index)},
		{"jaeger-service", fmt.Sprintf("node%d", index)},
		{"jaeger-address", "jaeger:6831"},
		{"definition-file", "/compose/cluster-definition.json"},
		{"lock-file", lockFile},
		{"monitoring-address", "0.0.0.0:3620"},
		{"validator-api-address", "0.0.0.0:3610"},
		{"p2p-external-hostname", fmt.Sprintf("node%d", index)},
		{"p2p-tcp-address", "0.0.0.0:3600"},
		{"p2p_udp_address", "0.0.0.0:3630"},
		{"p2p-bootnodes", "http://bootnode:3640/enr"},
		{"beacon-node-endpoint", beaconNode},
		{"simnet-validator-mock", fmt.Sprintf(`"%v"`, validatorMock)},
		{"simnet-beacon_mock", fmt.Sprintf(`"%v"`, beaconMock)},
		{"log-level", "debug"},
		{"feature-set", conf.FeatureSet},
	}
}

// LoadConfig returns the config loaded from disk.
func LoadConfig(dir string) (Config, error) {
	b, err := os.ReadFile(path.Join(dir, configFile))
	if err != nil {
		return Config{}, errors.Wrap(err, "load config")
	}

	var resp Config
	if err := json.Unmarshal(b, &resp); err != nil {
		return Config{}, errors.Wrap(err, "unmarshal Config")
	}

	return resp, nil
}
