// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"path/filepath"

	"github.com/fsnotify/fsnotify"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// watchFile returns a channel receiving a value each time the file at path is created or written, until ctx is
// cancelled, after which it is closed. The file's directory is watched, since an atomic write replaces the file.
// Changes arriving while one is pending are coalesced, watcher errors are logged.
func watchFile(ctx context.Context, path string) (<-chan struct{}, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, errors.Wrap(err, "create file watcher")
	}

	dir := filepath.Dir(path)

	err = watcher.Add(dir)
	if err != nil {
		_ = watcher.Close()

		return nil, errors.Wrap(err, "watch directory", z.Str("dir", dir))
	}

	baseName := filepath.Base(path)
	changes := make(chan struct{}, 1)

	go func() {
		defer close(changes)
		defer watcher.Close()

		for {
			select {
			case <-ctx.Done():
				return
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}

				log.Warn(ctx, "File watcher error", err, z.Str("path", path))
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				if filepath.Base(event.Name) != baseName {
					continue
				}

				if !event.Has(fsnotify.Create) && !event.Has(fsnotify.Write) {
					continue
				}

				select {
				case changes <- struct{}{}:
				default: // A change is already pending.
				}
			}
		}
	}()

	return changes, nil
}
