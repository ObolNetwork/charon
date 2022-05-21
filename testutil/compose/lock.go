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

	"github.com/goccy/go-yaml"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
)

// Lock creates a docker-compose.yml from a charon-compose.yml for generating keys and a cluster lock file.
func Lock(ctx context.Context, dir string) error {
	ctx = log.WithTopic(ctx, "lock")

	conf, err := loadConfig(dir)
	if err != nil {
		return err
	}

	var data tmplData
	switch conf.KeyGen {
	case keyGenCreate:
		// Only single node to call charon create cluster generate keys
		n := node{EnvVars: []kv{
			{"threshold", fmt.Sprint(conf.Threshold)},
			{"nodes", fmt.Sprint(conf.NumNodes)},
			{"cluster_dir", "/compose"},
		}}

		data = tmplData{
			NodeOnly:         true,
			ComposeDir:       dir,
			CharonImageTag:   conf.ImageTag,
			CharonEntrypoint: containerBinary,
			CharonCommand:    cmdCreateCluster,
			Nodes:            []node{n},
		}
	case keyGenDKG:

		var nodes []node
		for i := 0; i < conf.NumNodes; i++ {
			n := node{EnvVars: newNodeEnvs(i, true, true)}
			nodes = append(nodes, n)
		}

		data = tmplData{
			ComposeDir:       dir,
			CharonImageTag:   conf.ImageTag,
			CharonEntrypoint: containerBinary,
			CharonCommand:    cmdDKG,
			Nodes:            nodes,
		}
	default:
		return errors.New("supported keygen")
	}

	log.Info(ctx, "Creating docker-compose.yml")
	log.Info(ctx, "Create keys and cluster lock with: docker-compose up")

	return writeDockerCompose(dir, data)
}

// newNodeEnvs returns the default node environment variable to run a charon docker container.
func newNodeEnvs(index int, validatorMock, beaconMock bool) []kv {
	return []kv{
		{"data_dir", fmt.Sprintf("/compose/node%d", index)},
		{"jaeger_service", fmt.Sprintf("node%d", index)},
		{"jaeger_address", "jaeger:6831"},
		{"definition_file", "/compose/cluster-definition.json"},
		{"lock_file", "/compose/cluster-lock.json"},
		{"monitoring_address", "0.0.0.0:16001"},
		{"validator_api_address", "0.0.0.0:16002"},
		{"p2p_external_hostname", fmt.Sprintf("node%d", index)},
		{"p2p_tcp_address", "0.0.0.0:16003"},
		{"p2p_udp_address", "0.0.0.0:16004"},
		{"p2p_bootnodes", "http://bootnode:16000/enr"},
		{"simnet_validator_mock", fmt.Sprintf(`"%v"`, validatorMock)},
		{"simnet_beacon_mock", fmt.Sprintf(`"%v"`, beaconMock)},
		{"log_level", "info"},
	}
}

// loadConfig returns the config loaded from disk.
func loadConfig(dir string) (config, error) {
	b, err := os.ReadFile(path.Join(dir, composeFile))
	if err != nil {
		return config{}, errors.Wrap(err, "load config")
	}

	b, err = yaml.YAMLToJSON(b)
	if err != nil {
		return config{}, errors.Wrap(err, "yaml config")
	}

	var resp config
	if err := json.Unmarshal(b, &resp); err != nil {
		return config{}, errors.Wrap(err, "unmarshal config")
	}

	return resp, nil
}
