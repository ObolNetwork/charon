// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package testdata

import (
	"strconv"
	"time"
)

//go:generate go install github.com/obolnetwork/charon/app/genssz
//go:generate genssz

type Foo struct {
	ByteList []byte    `ssz:"ByteList[32]"`
	Number   int       `ssz:"uint64"`
	Bytes4   [4]byte   `ssz:"Bytes4"`
	Bytes2   []byte    `ssz:"Bytes2"`
	Bar      Bar       `ssz:"Composite"`
	Quxes    []Qux     `ssz:"CompositeList[256]"`
	QuxStrs  []Qux     `ssz:"CompositeList[256],toQuxStr"`
	UnixTime time.Time `ssz:"uint64,Unix"`
}

type Bar struct {
	Name string `ssz:"ByteList[32]"`
}

type Qux struct {
	Number int `ssz:"uint64"`
}

func (q Qux) toQuxStr() QuxStr {
	return QuxStr{Str: strconv.Itoa(q.Number)}
}

type QuxStr struct {
	Str string `ssz:"ByteList[32]"`
}

type ignored struct {
	Foo `json:"foo"`
	Bar Bar `json:"bar"`
	Qux Qux `json:"qux"`
}
