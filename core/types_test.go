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
)

func TestBackwardsCompatability(t *testing.T) {
	require.EqualValues(t, 0, core.DutyUnknown)
	require.EqualValues(t, 1, core.DutyProposer)
	require.EqualValues(t, 2, core.DutyAttester)
	require.EqualValues(t, 3, core.DutySignature)
	require.EqualValues(t, 4, core.DutyExit)
	require.EqualValues(t, 5, core.DutyBuilderProposer)
	require.EqualValues(t, 6, core.DutyBuilderRegistration)
	require.EqualValues(t, 7, core.DutyRandao)
	require.EqualValues(t, 8, core.DutyPrepareAggregator)
	require.EqualValues(t, 9, core.DutyAggregator)
	require.EqualValues(t, 10, core.DutySyncMessage)
	require.EqualValues(t, 11, core.DutyPrepareSyncContribution)
	require.EqualValues(t, 12, core.DutySyncContribution)
	require.EqualValues(t, 13, core.DutyInfoSync)
	// Add more types here.

	const sentinel = core.DutyType(14)
	for i := core.DutyUnknown; i <= sentinel; i++ {
		if i == core.DutyUnknown {
			require.False(t, i.Valid())
			require.Equal(t, "unknown", i.String())
		} else if i == sentinel {
			require.False(t, i.Valid())
			require.Equal(t, "", i.String())
		} else {
			require.True(t, i.Valid())
			require.NotEmpty(t, i.String())
		}
	}
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
