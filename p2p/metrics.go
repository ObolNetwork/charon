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

package p2p

import (
	"time"

	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	pingLatencies = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "p2p",
		Name:      "ping_latency_secs",
		Help:      "Ping latencies in seconds per peer",
	}, []string{"peer"})

	pingErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "p2p",
		Name:      "ping_error_total",
		Help:      "Total number of ping errors per peer",
	}, []string{"peer"})
)

func observePing(p peer.ID, d time.Duration) {
	pingLatencies.WithLabelValues(ShortID(p)).Observe(d.Seconds())
}

func incPingError(p peer.ID) {
	pingErrors.WithLabelValues(ShortID(p)).Inc()
}
