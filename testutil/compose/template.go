// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package compose

import (
	"bytes"
	"embed"
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

// TmplData is the docker-compose.yml template data.
type TmplData struct {
	ComposeDir string

	CharonImageTag   string
	CharonEntrypoint string
	CharonCommand    string

	Nodes []TmplNode
	VCs   []TmplVC

	Relay           bool
	Monitoring      bool
	Alerting        bool
	MonitoringPorts bool
}

// TmplVC represents a validator client service in a docker-compose.yml.
type TmplVC struct {
	Label   string
	Image   string
	Build   string
	Command string
	Ports   []port
}

// TmplNode represents a charon TmplNode service in a docker-compose.yml.
type TmplNode struct {
	ImageTag   string // ImageTag is empty by default, resulting in CharonImageTag being used.
	Entrypoint string // Entrypoint is empty by default, resulting in CharonEntrypoint being used.
	Command    string // Command is empty by default, resulting in CharonCommand being used.
	EnvVars    []kv
	Ports      []port
}

// kv is a key value pair.
type kv struct {
	Key   string
	Value string
}

// EnvKey returns the key formatted as env var: "data-dir" -> "DATA_DIR".
func (kv kv) EnvKey() string {
	return strings.ReplaceAll(strings.ToUpper(kv.Key), "-", "_")
}

// port is a port mapping in a docker-compose.yml.
type port struct {
	External int
	Internal int
}

// WriteDockerCompose generates the docker-compose.yml template and writes it to disk.
func WriteDockerCompose(dir string, data TmplData) error {
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
