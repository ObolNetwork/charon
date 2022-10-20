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

package app

import (
	"context"
	"fmt"
	"os"
	"path"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/obolnetwork/charon/app/lifecycle"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// wireMemoryMonitor wires a memory monitor that write heap dumps to disk when memory increases.
func wireMemoryMonitor(life *lifecycle.Manager, conf Config) {
	// TODO(corver): Remove this when issue resolved or before the next release (after v0.11.0).
	if conf.Log.Level != "debug" {
		return
	}
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartRest,
		lifecycle.HookFuncCtx(func(ctx context.Context) {
			dir := path.Join(path.Dir(conf.PrivKeyFile), "heapdumps")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				log.Warn(ctx, "Failed creating heap dump dir", err)
				return
			}

			monitorMemory(ctx, dir)
		}),
	)
}

// monitorMemory blocks until the context is closed.
//   - It reads the inuse memory every second,
//   - if it crosses the threshold,
//   - it writes a pprof heap dump to the dir,
//   - and increases the threshold.
func monitorMemory(ctx context.Context, dir string) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	const mb uint64 = 1 << 20
	threshold := 100 * mb

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := new(runtime.MemStats)
			runtime.ReadMemStats(stats)
			if stats.HeapInuse < threshold {
				continue
			}

			filename := fmt.Sprintf("heap_dump_%d.pb.gz", time.Now().Unix())
			filename = path.Join(dir, filename)

			file, err := os.Create(filename)
			if err != nil {
				log.Warn(ctx, "Failed creating heap dump file", err)
				return
			}

			err = pprof.Lookup("heap").WriteTo(file, 0)
			if err != nil {
				log.Warn(ctx, "Failed writing heap dump file", err)
				return
			}

			log.Info(ctx, "Inuse memory crossed threshold, dumped heap to file",
				z.U64("memory_mb", stats.HeapInuse>>20),
				z.U64("threshold_mb", threshold>>20),
				z.Str("file", filename),
			)

			threshold += 100 * mb
		}
	}
}
