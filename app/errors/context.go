// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
