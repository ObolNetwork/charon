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
	"embed"
	_ "embed"
	"os"
	"path"
	"strings"
	"text/template"

	"github.com/obolnetwork/charon/app/errors"
)

//go:embed docker-compose.template
var tmpl []byte

//go:embed static
var static embed.FS

// tmplData is the docker-compose.yml template data.
type tmplData struct {
	ComposeDir string

	CharonImageTag   string
	CharonEntrypoint string
	CharonCommand    string

	Nodes []node
	VCs   []vc

	Bootnode   bool
	Monitoring bool
}

// vc represents a validator client service in a docker-compose.yml.
type vc struct {
	Label   string
	Image   string
	Build   string
	Command string
	Ports   []port
}

// node represents a charon node service in a docker-compose.yml.
type node struct {
	EnvVars []kv
	Ports   []port
}

// kv is a key value pair.
type kv struct {
	Key   string
	Value string
}

func (kv kv) KeyUpper() string {
	return strings.ToUpper(kv.Key)
}

// port is a port mapping in a docker-compose.yml.
type port struct {
	External int
	Internal int
}

// writeDockerCompose generates the docker-compose.yml template and writes it to disk.
func writeDockerCompose(dir string, data tmplData) error {
	tpl, err := template.New("").Parse(string(tmpl))
	if err != nil {
		return errors.Wrap(err, "new template")
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return errors.Wrap(err, "exec template")
	}

	err = os.WriteFile(path.Join(dir, "docker-compose.yml"), buf.Bytes(), 0o755) //nolint:gosec
	if err != nil {
		return errors.Wrap(err, "write docker-compose")
	}

	return nil
}
