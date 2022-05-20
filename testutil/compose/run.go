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

	"github.com/obolnetwork/charon/app/log"
)

func Run(ctx context.Context, dir string) error {
	ctx = log.WithTopic(ctx, "run")

	conf, err := loadConfig(dir)
	if err != nil {
		return err
	}

	var nodes []node
	for i := 0; i < len(conf.Def.Operators); i++ {
		n := node{EnvVars: newNodeEnvs(i, true, true)}
		nodes = append(nodes, n)
	}

	data := tmplData{
		ComposeDir:       dir,
		CharonImageTag:   conf.ImageTag,
		CharonEntrypoint: containerBinary,
		CharonCommand:    cmdRun,
		Nodes:            nodes,
	}

	log.Info(ctx, "Created docker-compose.yml")
	log.Info(ctx, "Run the cluster with: docker-compose up")

	return writeDockerCompose(dir, data)
}
