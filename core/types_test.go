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

package core_test

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/tracer"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

func TestBackwardsCompatability(t *testing.T) {
	require.EqualValues(t, 0, core.DutyUnknown)
	require.EqualValues(t, 1, core.DutyProposer)
	require.EqualValues(t, 2, core.DutyAttester)
	require.EqualValues(t, 3, core.DutyRandao)
	// Add more types here.

	const sentinel = core.DutyType(4)
	for i := core.DutyUnknown; i <= sentinel; i++ {
		if i == core.DutyUnknown || i == sentinel {
			require.False(t, i.Valid())
		} else {
			require.True(t, i.Valid())
		}
	}
}

func TestGroupSignedData_Equal(t *testing.T) {
	testGroupSignedData1 := core.GroupSignedData{
		Data:      []byte("test data"),
		Signature: testutil.RandomCoreSignature(),
	}

	testGroupSignedData2 := core.GroupSignedData{
		Data:      []byte("test data"),
		Signature: testGroupSignedData1.Signature,
	}

	testGroupSignedData3 := core.GroupSignedData{
		Data:      []byte("test data 3"),
		Signature: testutil.RandomCoreSignature(),
	}

	testGroupSignedData4 := core.GroupSignedData{
		Data:      []byte("test data"),
		Signature: testutil.RandomCoreSignature(),
	}

	testGroupSignedData5 := core.GroupSignedData{
		Data:      []byte("test data 5"),
		Signature: testutil.RandomCoreSignature(),
	}

	require.True(t, testGroupSignedData1.Equal(testGroupSignedData2))
	require.False(t, testGroupSignedData1.Equal(testGroupSignedData3))
	require.False(t, testGroupSignedData1.Equal(testGroupSignedData4))
	require.False(t, testGroupSignedData1.Equal(testGroupSignedData5))
}

func TestWithDutySpanCtx(t *testing.T) {
	ctx := context.Background()
	stop, err := tracer.Init(tracer.WithStdOut(io.Discard))
	require.NoError(t, err)
	defer func() {
		require.NoError(t, stop(ctx))
	}()

	_, span1 := core.StartDutyTrace(ctx, core.Duty{}, "span1")
	_, span2 := core.StartDutyTrace(ctx, core.Duty{}, "span2")

	require.Equal(t, "7d0b160d5b04eac85dd1eaf0585c5b82", span1.SpanContext().TraceID().String())
	require.Equal(t, span1.SpanContext().TraceID(), span2.SpanContext().TraceID())
	require.NotEqual(t, span1.SpanContext().SpanID(), span2.SpanContext().SpanID())

	require.True(t, span1.SpanContext().IsValid())
	require.True(t, span1.SpanContext().IsSampled())

	require.True(t, span2.SpanContext().IsValid())
	require.True(t, span2.SpanContext().IsSampled())
}
