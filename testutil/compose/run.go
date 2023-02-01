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
	"bytes"
	"context"
	"fmt"
	"text/template"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// Run creates a docker-compose.yml from config.json to run the cluster.
func Run(ctx context.Context, dir string, conf Config) (TmplData, error) {
	if conf.Step != stepLocked {
		return TmplData{}, errors.New("compose config not locked, so can't be run", z.Any("step", conf.Step))
	}

	var (
		nodes []TmplNode
		vcs   []TmplVC
	)
	for i := 0; i < conf.NumNodes; i++ {
		typ := conf.VCs[i%len(conf.VCs)]
		vc, err := getVC(typ, i, conf.NumValidators, conf.InsecureKeys)
		if err != nil {
			return TmplData{}, err
		}
		vcs = append(vcs, vc)

		n := TmplNode{EnvVars: newNodeEnvs(i, conf, typ)}
		if !conf.DisableMonitoringPorts {
			for _, p := range charonPorts {
				p.External += 10000 * i
				n.Ports = append(n.Ports, p)
			}
		}
		nodes = append(nodes, n)
	}

	data := TmplData{
		ComposeDir:      dir,
		CharonImageTag:  conf.ImageTag,
		CharonCommand:   cmdRun,
		Nodes:           nodes,
		Relay:           true,
		Monitoring:      true,
		MonitoringPorts: !conf.DisableMonitoringPorts,
		VCs:             vcs,
	}

	log.Info(ctx, "Created docker-compose.yml")
	log.Info(ctx, "Run the cluster with: docker-compose up")

	if err := WriteDockerCompose(dir, data); err != nil {
		return TmplData{}, err
	}

	return data, nil
}

// getVC returns the validator client template data for the provided type and index.
func getVC(typ VCType, nodeIdx int, numVals int, insecure bool) (TmplVC, error) {
	vcByType := map[VCType]TmplVC{
		VCLighthouse: {
			Label: string(VCLighthouse),
			Build: "lighthouse",
		},
		VCTeku: {
			Label: string(VCTeku),
			Image: "consensys/teku:latest",
			Command: `|
      validator-client
      --network=auto
      --beacon-node-api-endpoint="http://node{{.NodeIdx}}:3600"
      {{range .TekuKeys}}--validator-keys="{{.}}"
      {{end -}}
      --validators-proposer-default-fee-recipient="0x0000000000000000000000000000000000000000"`,
		},
	}

	resp := vcByType[typ]
	if typ == VCTeku {
		var keys []string
		for i := 0; i < numVals; i++ {
			if insecure {
				keys = append(keys, fmt.Sprintf("/compose/node%d/validator_keys/keystore-insecure-%d.json:/compose/node%d/validator_keys/keystore-insecure-%d.txt", nodeIdx, i, nodeIdx, i))
			} else {
				keys = append(keys, fmt.Sprintf("/compose/node%d/validator_keys/keystore-%d.json:/compose/node%d/validator_keys/keystore-%d.txt", nodeIdx, i, nodeIdx, i))
			}
		}
		data := struct {
			TekuKeys []string
			NodeIdx  int
		}{
			NodeIdx:  nodeIdx,
			TekuKeys: keys,
		}
		var buf bytes.Buffer
		err := template.Must(template.New("").Parse(resp.Command)).Execute(&buf, data)
		if err != nil {
			return TmplVC{}, errors.Wrap(err, "teku template")
		}
		resp.Command = buf.String()
	}

	return resp, nil
}
