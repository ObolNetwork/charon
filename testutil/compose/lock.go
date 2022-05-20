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
	"fmt"
	"os"
	"path"

	"github.com/goccy/go-yaml"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
)

func Lock(ctx context.Context, dir string) error {
	ctx = log.WithTopic(ctx, "lock")

	conf, err := loadConfig(dir)
	if err != nil {
		return err
	}

	if conf.KeyGen != keyGenCreate {
		return errors.New("only keygen create supported")
	}

	// Only single node to call charon create cluster generate keys
	n := node{EnvVars: []kv{
		{"threshold", fmt.Sprint(conf.Def.Threshold)},
		{"nodes", fmt.Sprint(len(conf.Def.Operators))},
		{"cluster_dir", "/compose"},
	}}

	data := tmplData{
		NodeOnly:         true,
		ComposeDir:       dir,
		CharonImageTag:   conf.ImageTag,
		CharonEntrypoint: containerBinary,
		CharonCommand:    cmdCreateCluster,
		Nodes:            []node{n},
	}

	log.Info(ctx, "Created docker-compose.yml")
	log.Info(ctx, "Create keys and cluster lock with: docker-compose up")

	return writeDockerCompose(dir, data)
}

//nolint:deadcode // Busy implementing.
func newNodeEnvs(mockValidator bool) []kv {
	return []kv{
		{"jaeger_address", "jaeger:6831"},
		{"definition_file", "/compose/cluster-definition.json"},
		{"lock_file", "/compose/cluster-lock.json"},
		{"monitoring_address", "0.0.0.0:16001"},
		{"validator_api_address", "0.0.0.0:16002"},
		{"p2p_tcp_address", "0.0.0.0:16003"},
		{"p2p_udp_address", "0.0.0.0:16004"},
		{"p2p_bootnodes", "http://bootnode:16000/enr"},
		{"simnet_validator_mock", fmt.Sprint(mockValidator)},
		{"log_level", "info"},
	}
}

// loadConfig returns the config loaded from disk.
func loadConfig(dir string) (config, error) {
	b, err := os.ReadFile(path.Join(dir, composeFile))
	if err != nil {
		return config{}, errors.Wrap(err, "load config")
	}

	var resp config
	if err := yaml.Unmarshal(b, &resp); err != nil {
		return config{}, errors.Wrap(err, "unmarshal config")
	}

	return resp, nil
}
