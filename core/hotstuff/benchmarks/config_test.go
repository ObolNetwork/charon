// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package benchmarks_test

const (
	iterations = 10
)

type test struct {
	total     uint
	threshold uint
}

var tests = []test{
	{total: 4, threshold: 3},
	{total: 13, threshold: 9},
	{total: 22, threshold: 15},
}
