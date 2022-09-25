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

package promauto_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/promauto"
)

var testGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "test",
	Help: "",
}, []string{"label"})

func TestWrapRegisterer(t *testing.T) {
	promauto.WrapAndRegister(prometheus.Labels{
		"wrap_1": "1",
		"wrap_2": "2",
	})

	testGauge.WithLabelValues("0").Set(1)

	metrics, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	expect := map[string]string{
		"label":  "0",
		"wrap_1": "1",
		"wrap_2": "2",
	}

	for _, metricFam := range metrics {
		// Non promauto metrics do not contain wrapped labels.
		if *metricFam.Name != "test" {
			for _, metric := range metricFam.Metric {
				for _, label := range metric.Label {
					require.NotContains(t, *label.Name, "wrap_")
				}
			}

			continue
		}

		// Promauto metrics contain own and wrapped labels.
		for _, metric := range metricFam.Metric {
			for _, label := range metric.Label {
				require.Equal(t, expect[*label.Name], *label.Value)
				delete(expect, *label.Name)
			}
		}
	}

	require.Empty(t, expect)
}
