// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package privkeylock

import (
	"encoding/json"
	"os"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

var lockfileGracePeriod = func() time.Duration {
	return 5 * time.Second
}

type privkeyLockCtx struct {
	ContextStr string
	Timestamp  time.Time
}

func newLockCtx(contextStr string) privkeyLockCtx {
	return privkeyLockCtx{
		ContextStr: contextStr,
		Timestamp:  time.Now(),
	}
}

// New creates a private key lock file in path, writing ContextStr in it.
// If a private key lock file exists at path New returns an error, a clean-up function otherwise.
func New(path, contextStr string) (func() error, error) {
	if _, err := os.Stat(path); err == nil {
		roCtxFile, err := os.Open(path)
		if err != nil {
			return nil, errors.Wrap(err, "could not read private key lock file content even if present")
		}

		lctx := privkeyLockCtx{}
		if err := json.NewDecoder(roCtxFile).Decode(&lctx); err != nil {
			return nil, errors.Wrap(err, "cannot decode private key lock file content")
		}

		if time.Since(lctx.Timestamp) <= lockfileGracePeriod() {
			return nil, errors.New(
				"existing private key lock file found, another charon instance may be running on your machine, if not then you can delete that file",
				z.Str("path", path),
				z.Str("context", lctx.ContextStr),
			)
		}

		if err := roCtxFile.Close(); err != nil {
			return nil, errors.Wrap(err,
				"cannot close private key lock file, manually delete file at path to continue with execution",
				z.Str("path", path),
				z.Str("context", lctx.ContextStr),
			)
		}

		if err := os.Remove(path); err != nil {
			return nil, errors.Wrap(err,
				"could not remove old lock file whose timestamp is past grace period",
				z.Str("path", path),
				z.Str("context", lctx.ContextStr),
			)
		}

		// safety time has passed, overwrite lockfile with our own data
		if err := createPrivkeyLock(path, contextStr); err != nil {
			return nil, errors.Wrap(err,
				"cannot create private key lock file, manually delete file at path to continue with execution",
				z.Str("path", path),
				z.Str("context", lctx.ContextStr),
			)
		}

		return defaultCleanupFunc(path), nil
	} else if errors.Is(err, os.ErrNotExist) {
		if err := createPrivkeyLock(path, contextStr); err != nil {
			return nil, err
		}

		return defaultCleanupFunc(path), nil
	} else {
		return nil, errors.Wrap(err, "fatal error while handling private key lock file", z.Str("path", path))
	}
}

func defaultCleanupFunc(path string) func() error {
	return func() error {
		if err := os.Remove(path); err != nil {
			return errors.Wrap(err, "cannot remove private key lock file")
		}

		return nil
	}
}

// createPrivkeyLock creates a file in path with ContextStr and a timestamp written inside.
// It's an overzealous function: if it can't write exactly len(ContextStr, timestamp) bytes in path,
// it returns error.
func createPrivkeyLock(path, contextStr string) error {
	f, err := os.Create(path)
	if err != nil {
		return errors.Wrap(err, "cannot create private key lock file", z.Str("path", path))
	}

	lctx := newLockCtx(contextStr)
	content, err := json.Marshal(lctx)
	if err != nil {
		return errors.Wrap(err, "cannot marshal private key lock context")
	}

	amt, err := f.Write(content)
	if err != nil {
		return errors.Wrap(err, "cannot write context string in private key lock file", z.Str("path", path))
	}

	if amt != len(content) {
		return errors.New(
			"could not write entirety of context string in private key lock file",
			z.Str("path", path),
			z.Int("expected", len(content)),
			z.Int("got", amt),
		)
	}

	return nil
}
