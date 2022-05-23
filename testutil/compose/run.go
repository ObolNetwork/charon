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
	"io/fs"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
)

// Run creates a docker-compose.yml from config.json to run the cluster.
func Run(ctx context.Context, dir string) error {
	ctx = log.WithTopic(ctx, "run")

	conf, err := loadConfig(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return errors.New("compose config not found; maybe try `compose define` first")
	} else if err != nil {
		return err
	} else if conf.Step != stepLocked {
		return errors.New("compose config not locked yet, maybe try `compose lock` first")
	}

	var (
		nodes []node
		vcs   []vc
	)
	for i := 0; i < conf.NumNodes; i++ {
		n := node{EnvVars: newNodeEnvs(i, true, true)}
		nodes = append(nodes, n)

		typ := conf.VCs[i%len(conf.VCs)]
		vcs = append(vcs, vcByType[typ])
	}

	data := tmplData{
		ComposeDir:       dir,
		CharonImageTag:   conf.ImageTag,
		CharonEntrypoint: conf.entrypoint(),
		CharonCommand:    cmdRun,
		Nodes:            nodes,
		Bootnode:         true,
		Monitoring:       true,
		VCs:              vcs,
	}

	log.Info(ctx, "Created docker-compose.yml")
	log.Info(ctx, "Run the cluster with: docker-compose up")

	return writeDockerCompose(dir, data)
}

var vcByType = map[vcType]vc{
	vcLighthouse: {
		Label: string(vcLighthouse),
		Build: "lighthouse",
	},
	vcTeku: {
		Label: string(vcTeku),
		Image: "consensys/teku:latest",
		Command: `|
      validator-client
      --network=auto
      --beacon-node-api-endpoint="http://node1:16002"
      --validator-keys="/compose/node1:/compose/node1"
      --validators-proposer-default-fee-recipient="0x0000000000000000000000000000000000000000"`,
	},
}
