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

// Command genwrap provides a code generator for eth2client provider
// methods implemented by eth2multi.Service.
// It adds prometheus metrics and error wrapping.
package main

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/template"

	"golang.org/x/tools/imports"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"golang.org/x/tools/go/packages"
)

var (
	tpl = `package eth2wrap

// Code generated by genwrap.go. DO NOT EDIT.

import (
	"github.com/obolnetwork/charon/app/errors"
	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
{{- range .Imports}}
	{{.}}
{{- end}}
)

// Client defines all go-eth2-client interfaces used in charon.
type Client interface {
    eth2client.Service
    eth2exp.BeaconCommitteeSelectionAggregator
    eth2exp.SyncCommitteeSelectionAggregator
    BlockAttestationsProvider
    NodePeerCountProvider

    {{range .Providers}} eth2client.{{.}}
    {{end -}}
}

{{range .Methods}}
	{{.Doc}}
    {{- if not .Latency}}// Note this endpoint is cached in go-eth2-client.
    {{end -}}
	func (m multi) {{.Name}}({{.Params}}) ({{.ResultTypes}}) {
		const label = "{{.Label}}"
		{{if .Latency}}defer latency(label)() {{end}}


		{{.ResultNames}} := {{.DoFunc}}(ctx, m.clients,
			func(ctx context.Context, cl Client) ({{.ResultTypes}}){
				return cl.{{.Name}}({{.ParamNames}})
			},
			{{.SuccessFunc}}
		)

		if err != nil {
			incError(label)
			err = wrapError(ctx, err, label)
		}

		return {{.ResultNames}}
	}
{{end}}
`

	// interfaces defines all the interfaces to implement and whether to measure latency for each.
	interfaces = map[string]bool{
		"AggregateAttestationProvider":          true,
		"AggregateAttestationsSubmitter":        true,
		"AttestationDataProvider":               true,
		"AttestationsSubmitter":                 true,
		"AttesterDutiesProvider":                true,
		"BeaconBlockProposalProvider":           true,
		"BeaconBlockRootProvider":               false,
		"BeaconBlockSubmitter":                  true,
		"BeaconCommitteeSubscriptionsSubmitter": true,
		"BlindedBeaconBlockProposalProvider":    true,
		"BlindedBeaconBlockSubmitter":           true,
		"DepositContractProvider":               false,
		"DomainProvider":                        false,
		"EventsProvider":                        true,
		"ForkProvider":                          true,
		"ForkScheduleProvider":                  true,
		"GenesisProvider":                       false,
		"GenesisTimeProvider":                   false,
		"NodeSyncingProvider":                   true,
		"NodeVersionProvider":                   false,
		"ProposerDutiesProvider":                true,
		"ProposalPreparationsSubmitter":         false,
		"SlotDurationProvider":                  false,
		"SlotsPerEpochProvider":                 false,
		"SpecProvider":                          false,
		"SignedBeaconBlockProvider":             true,
		"SyncCommitteeDutiesProvider":           true,
		"SyncCommitteeContributionProvider":     true,
		"SyncCommitteeContributionsSubmitter":   true,
		"SyncCommitteeMessagesSubmitter":        true,
		"SyncCommitteeSubscriptionsSubmitter":   true,
		"ValidatorsProvider":                    true,
		"ValidatorRegistrationsSubmitter":       true,
		"VoluntaryExitSubmitter":                true,
	}

	// addImport indicates which types need hardcoded imports.
	addImport = map[string]string{
		"EventHandlerFunc": "eth2client",
	}

	// successFuncs indicates which endpoints have custom success functions.
	successFuncs = map[string]string{
		"NodeSyncing":          "isSyncStateOk",
		"AggregateAttestation": "isAggregateAttestationOk",
	}

	skipImport = map[string]bool{
		"\"time\"": true,
	}
)

type Method struct {
	Name        string
	Doc         string
	Latency     bool
	DoFunc      string
	SuccessFunc string
	params      []Field
	results     []Field
}

func (m Method) Label() string {
	return toSnakeCase(m.Name)
}

func (m Method) Params() string {
	var resp []string
	for _, param := range m.params {
		resp = append(resp, fmt.Sprintf("%s %s", param.Name, param.Type))
	}

	return strings.Join(resp, ", ")
}

func (m Method) Results() string {
	var resp []string
	for _, result := range m.results {
		resp = append(resp, fmt.Sprintf("%s %s", result.Name, result.Type))
	}

	return strings.Join(resp, ", ")
}

func (m Method) ParamNames() string {
	var resp []string
	for _, param := range m.params {
		resp = append(resp, param.Name)
	}

	return strings.Join(resp, ", ")
}

func (m Method) ResultNames() string {
	var resp []string
	for _, result := range m.results {
		resp = append(resp, result.Name)
	}

	return strings.Join(resp, ", ")
}

func (m Method) ResultTypes() string {
	var resp []string
	for _, result := range m.results {
		resp = append(resp, result.Type)
	}

	return strings.Join(resp, ", ")
}

type Field struct {
	Name string
	Type string
}

func main() {
	ctx := context.Background()
	err := run(ctx)
	if err != nil {
		log.Error(ctx, "Run error", err)
	}
}

func run(_ context.Context) error {
	pkgs, err := packages.Load(
		&packages.Config{
			Mode: packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedTypes,
		},
		"github.com/attestantio/go-eth2-client",
	)
	if err != nil {
		return errors.Wrap(err, "load package")
	}

	methods, providers, err := parseEth2Methods(pkgs[0])
	if err != nil {
		return err
	}

	imprts, err := parseImports(pkgs[0])
	if err != nil {
		return err
	}

	if err := writeTemplate(methods, providers, imprts); err != nil {
		return err
	}

	return nil
}

func parseImports(pkg *packages.Package) ([]string, error) {
	var (
		dups = make(map[string]bool)
		resp []string
	)

	for _, file := range pkg.Syntax {
		for _, imprt := range file.Imports {
			var b bytes.Buffer
			err := printer.Fprint(&b, pkg.Fset, imprt)
			if err != nil {
				return nil, errors.Wrap(err, "printf")
			}

			name := b.String()
			if skipImport[name] {
				continue
			}

			dups[name] = true
			resp = append(resp, name)
		}
	}

	return resp, nil
}

func writeTemplate(methods []Method, providers []string, imprts []string) error {
	t, err := template.New("").Parse(tpl)
	if err != nil {
		return errors.Wrap(err, "parse template")
	}

	sort.Strings(providers)

	var b bytes.Buffer
	err = t.Execute(&b, struct {
		Providers []string
		Methods   []Method
		Imports   []string
	}{
		Providers: providers,
		Methods:   methods,
		Imports:   imprts,
	})
	if err != nil {
		return errors.Wrap(err, "exec template")
	}

	filename := "eth2wrap_gen.go"
	out, err := imports.Process(filename, b.Bytes(), nil)
	if err != nil {
		return errors.Wrap(err, "format")
	}

	err = os.WriteFile(filename, out, 0o644) //nolint:gosec
	if err != nil {
		return errors.Wrap(err, "write file")
	}

	return nil
}

func parseEth2Methods(pkg *packages.Package) ([]Method, []string, error) {
	var (
		methods   []Method
		providers []string
	)
	for _, file := range pkg.Syntax {
		for _, decl := range file.Decls {
			gendecl, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}

			if gendecl.Tok != token.TYPE {
				continue
			}

			for _, spec := range gendecl.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}

				iface, ok := typeSpec.Type.(*ast.InterfaceType)
				if !ok {
					continue
				}

				latency, add := interfaces[typeSpec.Name.Name]
				if !add {
					continue
				}

				providers = append(providers, typeSpec.Name.Name)

				for _, method := range iface.Methods.List {
					fnType, ok := method.Type.(*ast.FuncType)
					if !ok {
						continue
					}

					name := method.Names[0].Name

					var params []Field
					for _, param := range fnType.Params.List {
						var b bytes.Buffer
						err := printer.Fprint(&b, pkg.Fset, param.Type)
						if err != nil {
							return nil, nil, errors.Wrap(err, "printf")
						}

						typ := b.String()
						if imprt, ok := addImport[typ]; ok {
							typ = imprt + "." + typ
						}

						field := Field{
							Name: param.Names[0].Name,
							Type: typ,
						}

						params = append(params, field)
					}

					var results []Field
					for i, result := range fnType.Results.List {
						var b bytes.Buffer
						err := printer.Fprint(&b, pkg.Fset, result.Type)
						if err != nil {
							return nil, nil, errors.Wrap(err, "printf")
						}

						name := fmt.Sprintf("res%d", i)
						if i == fnType.Results.NumFields()-1 {
							name = "err"
						}

						field := Field{
							Name: name,
							Type: b.String(),
						}

						results = append(results, field)
					}

					var doc string
					if method.Doc != nil {
						for _, line := range strings.Split(strings.TrimSpace(method.Doc.Text()), "\n") {
							doc += "// " + line + "\n"
						}
					}

					successFunc := "nil,"
					if fn, ok := successFuncs[name]; ok {
						successFunc = fn + ","
					}

					dofunc := "provide"
					if len(results) == 1 {
						dofunc = "submit"
						successFunc = ""
					}

					methods = append(methods, Method{
						Name:        name,
						Doc:         doc,
						Latency:     latency,
						DoFunc:      dofunc,
						SuccessFunc: successFunc,
						params:      params,
						results:     results,
					})
				}
			}
		}
	}

	return methods, providers, nil
}

var (
	matchFirstCap = regexp.MustCompile("(.)([A-Z][a-z]+)")
	matchAllCap   = regexp.MustCompile("([a-z0-9])([A-Z])")
)

func toSnakeCase(str string) string {
	snake := matchFirstCap.ReplaceAllString(str, "${1}_${2}")
	snake = matchAllCap.ReplaceAllString(snake, "${1}_${2}")

	return strings.ToLower(snake)
}
