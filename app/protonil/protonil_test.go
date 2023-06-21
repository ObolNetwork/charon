// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package protonil_test

import (
	"testing"

	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/protonil"
	v1 "github.com/obolnetwork/charon/app/protonil/testdata/v1"
	"github.com/obolnetwork/charon/testutil"
)

func TestCheck(t *testing.T) {
	tests := []struct {
		name    string
		m1      *v1.M1
		wantErr string
	}{
		{
			name:    "nil",
			m1:      nil,
			wantErr: "nil protobuf message",
		},
		{
			name:    "zero m1, nil m2",
			m1:      &v1.M1{},
			wantErr: "nil proto field",
		},
		{
			name: "all populated",
			m1: &v1.M1{
				Name: "m1",
				M2: &v1.M2{
					Name:       "m2",
					M3:         &v1.M3{Name: "m3"},
					M3Optional: &v1.M3{Name: "m3_opt"},
				},
				M2Optional: &v1.M2{
					Name:       "m2_opt",
					M3:         &v1.M3{Name: "m3"},
					M3Optional: &v1.M3{Name: "m3_opt"},
				},
			},
			wantErr: "",
		},
		{
			name: "optionals nil",
			m1: &v1.M1{
				Name: "m1",
				M2: &v1.M2{
					Name:       "m2",
					M3:         &v1.M3{Name: "m3"},
					M3Optional: nil,
				},
				M2Optional: nil,
			},
			wantErr: "",
		},
		{
			name: "nil m3 in optional m2",
			m1: &v1.M1{
				Name: "m1",
				M2: &v1.M2{
					Name: "m2",
					M3:   &v1.M3{Name: "m3"},
				},
				M2Optional: &v1.M2{
					Name: "m2_opt",
					M3:   nil,
				},
			},
			wantErr: "inner message field: nil proto field",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := protonil.Check(test.m1)
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
			} else {
				testutil.RequireNoError(t, err)
			}
		})
	}
}

func TestFuzzCheck(t *testing.T) {
	fuzzer := fuzz.New().NilChance(0)
	m1 := new(v1.M1)
	fuzzer.Fuzz(m1)
	testutil.RequireNoError(t, protonil.Check(m1))
}

func BenchmarkCheck(b *testing.B) {
	fuzzer := fuzz.New()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		m1 := new(v1.M1)
		fuzzer.Fuzz(m1)
		b.StartTimer()
		_ = protonil.Check(m1)
	}
}

func TestMaxIndex(t *testing.T) {
	err := protonil.Check(new(v1.MaxIndex))
	require.ErrorContains(t, err, "this should never happen")
}
