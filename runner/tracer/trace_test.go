// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	_, span = tracer.Start(ctx, "inner")
	defer span.End()
}
