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

package errors

import (
	"context"

	"github.com/obolnetwork/charon/app/z"
)

// WithCtxErr returns a copy of the context that wraps the errors returned by
// context.Err() with the provided message and fields.
func WithCtxErr(ctx context.Context, wrapMsg string, fields ...z.Field) context.Context {
	return ctxWrap{
		Context: ctx,
		wrapMsg: wrapMsg,
		fields:  fields,
	}
}

type ctxWrap struct {
	context.Context

	wrapMsg string
	fields  []z.Field
}

func (c ctxWrap) Err() error {
	err := c.Context.Err()
	if err == nil {
		return nil
	}

	return Wrap(err, c.wrapMsg, c.fields...)
}
