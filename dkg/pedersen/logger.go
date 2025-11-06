// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen

import (
	"context"
	"fmt"
	"strings"

	kdkg "github.com/drand/kyber/share/dkg"

	"github.com/obolnetwork/charon/app/log"
)

type kyberLogger struct {
	logCtx context.Context
}

var _ kdkg.Logger = (*kyberLogger)(nil)

func newLogger(logCtx context.Context) *kyberLogger {
	return &kyberLogger{
		logCtx: logCtx,
	}
}

func (l *kyberLogger) Error(keyvals ...any) {
	msg, err := concatKeyVals(keyvals)
	log.Error(l.logCtx, msg, err)
}

func (l *kyberLogger) Info(keyvals ...any) {
	msg, _ := concatKeyVals(keyvals)
	log.Info(l.logCtx, msg)
}

func concatKeyVals(keyvals []any) (str string, err error) {
	// In fact, all keyvals are strings except errors
	var strSb38 strings.Builder

	for _, v := range keyvals {
		if maybeErr, ok := v.(error); ok {
			err = maybeErr
		} else {
			strSb38.WriteString(fmt.Sprintf("%v", v))
		}
	}

	str += strSb38.String()

	return str, err
}
