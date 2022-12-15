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

package promrated

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -update -clean

func TestGetValidationStatistics(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v0/eth/validators/0xA/effectiveness", r.URL.Path)
		require.Equal(t, "1", r.URL.Query()["size"][0])
		_, _ = w.Write([]byte(ratedFixture))
	}))
	defer ts.Close()

	validator := validator{ClusterName: "test-cluster", ClusterHash: "hash", ClusterNetwork: "goerli", PubKey: "0xA"}

	vals, err := getValidationStatistics(context.Background(), ts.URL, validator)
	assert.NoError(t, err)
	testutil.RequireGoldenJSON(t, vals)
}

const ratedFixture = `
{
  "page": {
      "from": null,
      "size": 1,
      "granularity": "day",
      "filterType": "day"
  },
  "total": 115,
  "data": [
      {
          "avgInclusionDelay": 1.4330357142857142,
          "uptime": 0.9955555555555555,
          "avgCorrectness": 0.9300595238095238,
          "attesterEffectiveness": 64.61289950386524,
          "proposerEffectiveness": null,
          "validatorEffectiveness": 64.61289950386524
      }
  ],
  "next": "/v0/eth/validators/379356/effectiveness?size=1&from=629&granularity=day&filterType=day"
}`
