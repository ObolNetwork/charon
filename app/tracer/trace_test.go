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

package tracer_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"github.com/obolnetwork/charon/app/tracer"
)

func TestDefaultNoopTracer(_ *testing.T) {
	// This just shouldn't panic.
	ctx, span := tracer.Start(context.Background(), "root")
	defer span.End()

	inner(ctx)
}

func TestStdOutTracer(t *testing.T) {
	ctx := context.Background()

	var buf bytes.Buffer
	stop, err := tracer.Init(tracer.WithStdOut(&buf))
	require.NoError(t, err)

	var span trace.Span
	ctx, span = tracer.Start(ctx, "root")
	inner(ctx)
	span.End()

	require.NoError(t, stop(ctx))

	var m map[string]interface{}
	d := json.NewDecoder(&buf)

	err = d.Decode(&m)
	require.NoError(t, err)
	require.Equal(t, "inner", m["Name"])

	err = d.Decode(&m)
	require.NoError(t, err)
	require.Equal(t, "root", m["Name"])
}

func inner(ctx context.Context) {
	var span trace.Span
	_, span = tracer.Start(ctx, "inner")
	defer span.End()
}
