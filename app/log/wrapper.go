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

package log

import (
	"go.uber.org/zap"

	"github.com/obolnetwork/charon/app/log/loki"
)

// multiLogger wraps multiple zap loggers and implements zapLogger.
type multiLogger []zapLogger

func (m multiLogger) Debug(msg string, fields ...zap.Field) {
	for _, l := range m {
		l.Debug(msg, fields...)
	}
}

func (m multiLogger) Info(msg string, fields ...zap.Field) {
	for _, l := range m {
		l.Info(msg, fields...)
	}
}

func (m multiLogger) Warn(msg string, fields ...zap.Field) {
	for _, l := range m {
		l.Warn(msg, fields...)
	}
}

func (m multiLogger) Error(msg string, fields ...zap.Field) {
	for _, l := range m {
		l.Error(msg, fields...)
	}
}

// lokiWriter wraps a loki client and implements zap.SyncWriter.
type lokiWriter struct {
	cl *loki.Client
}

func (l lokiWriter) Write(line []byte) (n int, err error) {
	l.cl.Add(string(line))
	return len(line), nil
}

func (lokiWriter) Sync() error {
	return nil
}
