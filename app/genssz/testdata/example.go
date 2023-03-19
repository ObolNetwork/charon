// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package testdata

//go:generate go install github.com/obolnetwork/charon/app/genssz
//go:generate genssz

type Foo struct {
	ByteList []byte  `ssz:"ByteList[32]"`
	Number   int     `ssz:"uint64"`
	Bytes4   [4]byte `ssz:"Bytes4"`
	Bytes2   []byte  `ssz:"Bytes2"`
	Bar      Bar     `ssz:"Composite"`
	Quxes    []Qux   `ssz:"CompositeList[256]"`
}

type Bar struct {
	Name string `ssz:"ByteList[32]"`
}

type Qux struct {
	Number int `ssz:"uint64"`
}
