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
	"reflect"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/promauto"
)

func TestWrapRegisterer(t *testing.T) {
	simpleGge := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sample_gge",
		Help: "helpSampleGge",
	}, []string{"prom"})
	simpleGge.WithLabelValues("obol-prom").Set(1)

	promauto.WrapAndRegister(prometheus.Labels{
		"cluster_hash":      "lockHash",
		"cluster_name":      "test-cluster",
		"cluster_peer_name": "charon",
	})

	expected := map[string]string{
		"cluster_hash":      "lockHash",
		"cluster_name":      "test-cluster",
		"cluster_peer_name": "charon",
		"prom":              "obol-prom",
	}

	got, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	actual := make(map[string]string)
	labels := got[len(got)-1].Metric[0].Label
	for _, l := range labels {
		actual[*l.Name] = *l.Value
	}

	require.True(t, reflect.DeepEqual(expected, actual))
}
