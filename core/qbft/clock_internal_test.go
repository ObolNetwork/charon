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

package qbft

import (
	"sync"
	"time"
)

// fakeClock is a fake clock providing fake timers.
type fakeClock struct {
	mu    sync.Mutex
	t0    time.Time
	now   time.Time
	chans []chan time.Time
	times []time.Time
	stop  chan struct{}
}

// NewTimer returns a new timer channel and stop function.
func (c *fakeClock) NewTimer(d time.Duration) (<-chan time.Time, func()) {
	c.mu.Lock()
	defer c.mu.Unlock()

	i := len(c.chans)
	ch := make(chan time.Time, 1)
	c.chans = append(c.chans, ch)
	c.times = append(c.times, c.now.Add(d))

	return ch, func() {
		c.mu.Lock()
		defer c.mu.Unlock()

		c.chans[i] = nil
	}
}

// NowStr returns the current time as a debug string.
func (c *fakeClock) NowStr() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now.Format("04:05.000")
}

// SinceT0 returns the duration since zero time.
func (c *fakeClock) SinceT0() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now.Sub(c.t0)
}

// Advance updates current time and triggers any elapsed timers.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)

	for i, ch := range c.chans {
		if ch == nil {
			continue
		}

		deadline := c.times[i]

		if deadline.After(c.now) {
			continue
		}

		ch <- deadline

		c.chans[i] = nil
	}
}
