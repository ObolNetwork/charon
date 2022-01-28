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
	"fmt"
	"strings"
	"testing"

	pkgerrors "github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
)

func TestWithContext(t *testing.T) {
	buf := setup(t)

	ctx1 := context.Background()
	ctx2 := log.WithContext(ctx1).Int("wrap2", 2).Ctx()
	ctx3 := log.WithContext(ctx2).Str("wrap3", "3").Ctx()

	log.Debug(ctx1).Int("ctx1", 1).Msg("msg1")
	log.Info(ctx2).Int("ctx2", 2).Msg("msg2")
	log.Warn(ctx3).Int("ctx3", 3).Msg("msg3")

	expect := `12:00AM DBG app/log/log_test.go:- > msg1 ctx1=1
12:00AM INF app/log/log_test.go:- > msg2 ctx2=2 wrap2=2
12:00AM WRN app/log/log_test.go:- > msg3 ctx3=3 wrap2=2 wrap3=3
`
	require.Equal(t, expect, buf.String())
}

func TestErrorWrap(t *testing.T) {
	buf := setup(t)

	err1 := errors.New("first").Int("1", 1)
	err2 := errors.Wrap(err1, "second").Int("2", 2)
	err3 := errors.Wrap(err2, "third").Int("3", 3)

	ctx := context.Background()
	log.Error(ctx, err1).Msg("err1")
	log.Error(ctx, err2).Msg("err2")
	log.Error(ctx, err3).Msg("err3")

	// TODO(corver): Improve console error formatting.
	expect := `12:00AM ERR app/log/log_test.go:- > err1 error={"fields":[{"1":1}],"message":"first"} stack="errors.go\nlog_test.go\ntesting.go\nasm_arm64.s\n"
12:00AM ERR app/log/log_test.go:- > err2 error={"fields":[{"2":2},{"1":1}],"message":"second: first"} stack="errors.go\nlog_test.go\ntesting.go\nasm_arm64.s\n"
12:00AM ERR app/log/log_test.go:- > err3 error={"fields":[{"3":3},{"2":2},{"1":1}],"message":"third: second: first"} stack="errors.go\nlog_test.go\ntesting.go\nasm_arm64.s\n"
`
	require.Equal(t, expect, buf.String())
}

// setup returns a buffer that logs are written to and stubs non-deterministic logging fields.
func setup(t *testing.T) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer

	log.InitConsoleLogger(
		func(w *zerolog.ConsoleWriter) {
			w.Out = &buf
			w.NoColor = true
		})

	// Stub time for test to be deterministic
	tff := zerolog.TimeFieldFormat

	zerolog.TimeFieldFormat = "-"

	t.Cleanup(func() {
		zerolog.TimeFieldFormat = tff
	})

	// Exclude line numbers for test to be deterministic
	cmf := zerolog.CallerMarshalFunc

	zerolog.CallerMarshalFunc = func(file string, _ int) string {
		const trimBefore = "charon/"
		if i := strings.Index(file, trimBefore); i > 0 {
			file = file[i+len(trimBefore):]
		}

		return file + ":-"
	}
	t.Cleanup(func() {
		zerolog.CallerMarshalFunc = cmf
	})

	// Exclude line numbers for test to be deterministic
	esm := zerolog.ErrorStackMarshaler

	zerolog.ErrorStackMarshaler = func(err error) interface{} {
		type stackTracer interface {
			StackTrace() pkgerrors.StackTrace
		}
		//nolint:errorlint
		sterr, ok := err.(stackTracer)
		if !ok {
			return nil
		}

		var buf bytes.Buffer
		for _, frame := range sterr.StackTrace() {
			_, _ = fmt.Fprintf(&buf, "%s\n", frame)
		}

		return buf.String()
	}
	t.Cleanup(func() {
		zerolog.ErrorStackMarshaler = esm
	})

	return &buf
}
