// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package main

import (
	"strconv"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

type Data struct {
	Types []Type
}

type Type struct {
	Name   string
	Fields []Field
}

func (t Type) Abbr() string {
	var lastUpper rune
	for _, r := range t.Name {
		if r >= 'A' && r <= 'Z' {
			lastUpper = r
		}
	}

	if lastUpper == 0 {
		return strings.ToLower(t.Name[0:1])
	}

	return strings.ToLower(string(lastUpper))
}

type Field struct {
	Index     int
	Name      string
	Transform string
	SSZTag    string
}

func (f Field) IsComposite() bool {
	return f.SSZTag == "Composite"
}

func (f Field) IsCompositeList() bool {
	return strings.HasPrefix(f.SSZTag, "CompositeList")
}

func (f Field) IsByteList() bool {
	return strings.HasPrefix(f.SSZTag, "ByteList")
}

func (f Field) IsBytesN() bool {
	return strings.HasPrefix(f.SSZTag, "Bytes")
}

func (f Field) IsUint64() bool {
	return f.SSZTag == "uint64"
}

func (f Field) MustSize() int {
	size, err := f.Size()
	if err != nil {
		panic(err)
	}

	return size
}

func (f Field) Size() (int, error) {
	var intStr string
	if f.IsByteList() || f.IsCompositeList() {
		openIdx := strings.Index(f.SSZTag, "[")
		closeIdx := strings.Index(f.SSZTag, "]")
		if openIdx == -1 || closeIdx == -1 {
			return 0, errors.New("field has malformed size tag", z.Str("field_name", f.Name), z.Str("tag", f.SSZTag))
		}

		intStr = f.SSZTag[openIdx+1 : closeIdx]
	} else if f.IsBytesN() {
		if len(f.SSZTag) < 6 {
			return 0, errors.New("field has malformed size tag", z.Str("field_name", f.Name), z.Str("tag", f.SSZTag))
		}

		intStr = f.SSZTag[5:]
	}

	size, err := strconv.Atoi(intStr)
	if err != nil {
		return 0, errors.Wrap(err, "parse size", z.Str("field", f.Name), z.Str("tag", f.SSZTag))
	}

	return size, nil
}
