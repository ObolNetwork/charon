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

package log_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

func TestWithContext(t *testing.T) {
	buf := setup(t)

	ctx1 := context.Background()
	ctx2 := log.WithCtx(ctx1, z.Int("wrap2", 2))
	ctx3a := log.WithCtx(ctx2, z.Str("wrap3", "a"))
	ctx3b := log.WithCtx(ctx2, z.Str("wrap3", "b")) // Should override ctx3a field of same name.

	log.Debug(ctx1, "msg1", z.Int("ctx1", 1))
	log.Info(ctx2, "msg2", z.Int("ctx2", 2))
	log.Warn(ctx3a, "msg3a")
	log.Warn(ctx3b, "msg3b")

	expect := `00:00 DEBUG log/log_test.go:41 msg1 {"ctx1": 1}
00:00 INFO log/log_test.go:42 msg2 {"ctx2": 2, "wrap2": 2}
00:00 WARN log/log_test.go:43 msg3a {"wrap3": "a", "wrap2": 2}
00:00 WARN log/log_test.go:44 msg3b {"wrap3": "b", "wrap2": 2}
`
	require.Equal(t, expect, buf.String())
}

func TestErrorWrap(t *testing.T) {
	buf := setup(t)

	err1 := errors.New("first", z.Int("1", 1))
	err2 := errors.Wrap(err1, "second", z.Uint("2", 2))
	err3 := errors.Wrap(err2, "third", z.F64("3", 3))

	ctx := context.Background()
	log.Error(ctx, "err1", err1)
	log.Error(ctx, "err2", err2)
	log.Error(ctx, "err3", err3)

	expect := `00:00 ERROR log/log_test.go:62 err1: first {"1": 1}
	app/log/log_test.go:57 .TestErrorWrap
00:00 ERROR log/log_test.go:63 err2: second: first {"2": 2, "1": 1}
	app/log/log_test.go:57 .TestErrorWrap
00:00 ERROR log/log_test.go:64 err3: third: second: first {"3": 3, "2": 2, "1": 1}
	app/log/log_test.go:57 .TestErrorWrap
`

	require.Equal(t, expect, buf.String())
}

// setup returns a buffer that logs are written to and stubs non-deterministic logging fields.
func setup(t *testing.T) *bytes.Buffer {
	t.Helper()

	var buf zaptest.Buffer

	encConfig := zap.NewDevelopmentConfig().EncoderConfig
	encConfig.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString("00:00")
	}
	encConfig.ConsoleSeparator = " "

	log.InitLoggerForT(t, encConfig, &buf)

	return &buf.Buffer
}
