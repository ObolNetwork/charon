// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package protonil_test

import (
	"fmt"
	"testing"

	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/protonil"
	v1 "github.com/obolnetwork/charon/app/protonil/testdata/v1"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
	corepb "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/testutil"
)

func TestCheck(t *testing.T) {
	tests := []struct {
		name    string
		msg     proto.Message
		wantErr string
	}{
		{
			name:    "nil",
			msg:     nil,
			wantErr: "nil protobuf message",
		},
		{
			name:    "zero msg, nil m2",
			msg:     &v1.M1{},
			wantErr: "nil proto field",
		},
		{
			name: "all populated",
			msg: &v1.M1{
				Name: "msg",
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
			msg: &v1.M1{
				Name: "msg",
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
			msg: &v1.M1{
				Name: "msg",
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
		{
			name:    "zero m4",
			msg:     &v1.M4{},
			wantErr: "",
		},
		{
			name: "m4 with non-empty containers",
			msg: &v1.M4{
				M3Map: map[string]*v1.M3{
					"k0": {Name: "v0"},
					"k1": {Name: "v1"},
				},
				M3List: []*v1.M3{
					{Name: "elem0"},
					{Name: "elem1"},
				},
			},
			wantErr: "",
		},
		{
			name: "m4 with nil map value",
			msg: &v1.M4{
				M3Map: map[string]*v1.M3{
					"k0": nil,
					"k1": {Name: "v1"},
				},
			},
			wantErr: "map value: nil protobuf message",
		},
		{
			name: "m4 with nil list element",
			msg: &v1.M4{
				M3List: []*v1.M3{
					nil,
					{Name: "elem1"},
				},
			},
			wantErr: "list element: nil protobuf message",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := protonil.Check(test.msg)
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
			} else {
				testutil.RequireNoError(t, err)
			}
		})
	}
}

func TestFuzz(t *testing.T) {
	tests := []proto.Message{
		new(v1.M1),
		new(v1.M2),
		new(v1.M3),
		new(v1.M4),
		new(manifestpb.Cluster),
		new(manifestpb.SignedMutation),
		new(manifestpb.SignedMutationList),
		new(manifestpb.LegacyLock),
		new(corepb.QBFTMsg),
		new(corepb.PriorityScoredResult),
		new(corepb.SniffedConsensusInstance),
	}

	fuzzer := fuzz.New().NilChance(0)
	for _, msg := range tests {
		t.Run(fmt.Sprintf("%T", msg), func(t *testing.T) {
			fuzzer.Fuzz(msg)
			testutil.RequireNoError(t, protonil.Check(msg))
		})
	}
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

func TestAttack(t *testing.T) {
	attack := &v1.Attack{
		Name: "attack",
		M2: &v1.M2{
			Name: "m2",
			M3:   &v1.M3{Name: "m3"},
		},
		M3Unknown: nil,                    // This is ignored
		M3Attack:  &v1.M3{Name: "attack"}, // This is also ignored
	}

	b, err := proto.Marshal(attack)
	require.NoError(t, err)

	m1 := new(v1.M1)
	err = proto.Unmarshal(b, m1)
	require.NoError(t, err)

	err = protonil.Check(m1)
	require.NoError(t, err)
}
