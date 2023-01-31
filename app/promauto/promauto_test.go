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
	testGauge.WithLabelValues("0").Set(1)

	labels := prometheus.Labels{
		"wrap_1": "1",
		"wrap_2": "2",
	}

	registry, err := promauto.NewRegistry(labels)
	require.NoError(t, err)
	metrics, err := registry.Gather()
	require.NoError(t, err)
	require.True(t, len(metrics) > 1)

	var foundTest bool
	for _, metricFam := range metrics {
		// All metrics contain own and registered labels.
		for _, metric := range metricFam.Metric {
			notFound := make(prometheus.Labels)
			for k, v := range labels {
				notFound[k] = v
			}
			for _, label := range metric.Label {
				v, ok := notFound[*label.Name]
				if !ok {
					continue
				}
				require.Equal(t, v, *label.Value)
				delete(notFound, *label.Name)
			}

			require.Empty(t, notFound)
		}
		if *metricFam.Name == "test" {
			foundTest = true
		}
	}

	require.True(t, foundTest)
}
