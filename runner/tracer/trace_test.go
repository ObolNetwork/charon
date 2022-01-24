package tracer_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"github.com/obolnetwork/charon/runner/tracer"
)

func TestDefaultNoopTracer(t *testing.T) {
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
	ctx, span = tracer.Start(ctx, "inner")
	defer span.End()
}
