// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Command genssz generates ssz hashing code for structs in given go package.
// Structs need to be tagged with `ssz:"<ssz-type>"` to be included.
//
//	SSZ-types supported are:
//	- `uint64`
//	- `ByteList[<size>]`
//	- `Bytes<length>`
//	- `Composite`
//	- `CompositeList[<size>]`
//
// The `ByteList` and `CompositeList` types are expected to be slices.
//
// An optional transform function can be specified as a tag-option.
// E.g. `Timestamp time.Time ssz:"uint64,Unix"` will result in `uint64(foo.Timestamp.Unix())`.
package main

import (
	"bytes"
	"context"
	"flag"
	"go/ast"
	"os"
	"os/exec"
	"path"
	"strings"
	"text/template"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/imports"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

var pkgFlag = flag.String("package", "", "The fully qualified go package to generate code for. Defaults to the working dir package.")

func main() {
	ctx := context.Background()

	pkg, err := getPkg()
	if err != nil {
		log.Error(context.Background(), "Failed to get module", err)
		os.Exit(1)
	}

	err = run(ctx, pkg)
	if err != nil {
		log.Error(ctx, "Fatal run error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, packageName string) error {
	pkgs, err := packages.Load(
		&packages.Config{
			Mode: packages.NeedSyntax |
				packages.NeedTypesInfo |
				packages.NeedFiles |
				packages.NeedCompiledGoFiles |
				packages.NeedTypes,
		},
		packageName,
	)
	if err != nil {
		return errors.Wrap(err, "load package")
	} else if len(pkgs) != 1 {
		return errors.New("expected 1 package")
	}

	var types []Type
	for _, file := range pkgs[0].Syntax {
		types = append(types, parseFile(file)...)
	}

	if len(types) == 0 {
		log.Info(ctx, "No structs with ssz tags found in package", z.Str("package", packageName))
		return nil
	}

	err = writeTemplate(types, "ssz_gen.go", path.Base(packageName))
	if err != nil {
		return errors.Wrap(err, "write template")
	}

	return nil
}

func parseFile(astFile *ast.File) []Type {
	var types []Type

	for _, decl := range astFile.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}

		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}

			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				continue
			}

			if structType.Fields == nil {
				continue
			}

			var fields []Field
			for i, field := range structType.Fields.List {
				if field.Tag == nil {
					continue
				}

				tag := strings.Trim(field.Tag.Value, "`")
				if tag == "" || !strings.Contains(tag, "ssz:") {
					continue
				}

				sszTagIndex := strings.Index(tag, "ssz:\"") + 5 // Add 5 to skip the 'ssz:"' prefix
				sszTagLen := strings.Index(tag[sszTagIndex:], `"`)

				split := strings.Split(tag[sszTagIndex:sszTagIndex+sszTagLen], ",")
				var transform string
				if len(split) > 1 {
					transform = "." + split[1] + "()"
				}

				fields = append(fields, Field{
					Index:     i,
					Name:      field.Names[0].Name,
					SSZTag:    split[0],
					Transform: transform,
				})
			}

			if len(fields) == 0 {
				continue
			}
			types = append(types, Type{
				Name:   typeSpec.Name.Name,
				Fields: fields,
			})
		}
	}

	return types
}

func writeTemplate(types []Type, filename string, pkg string) error {
	t, err := template.New("").Parse(tmpl)
	if err != nil {
		return errors.Wrap(err, "parse template")
	}

	var b bytes.Buffer
	err = t.Execute(&b, struct {
		Package string
		Types   []Type
	}{
		Package: pkg,
		Types:   types,
	})
	if err != nil {
		return errors.Wrap(err, "exec template")
	}

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

func getPkg() (string, error) {
	if *pkgFlag != "" {
		return *pkgFlag, nil
	}

	out, err := exec.Command("go", "list", ".").Output()
	if err != nil {
		return "", errors.Wrap(err, "get package")
	}

	return strings.TrimSpace(string(out)), nil
}
