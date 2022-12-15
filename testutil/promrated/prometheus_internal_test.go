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

func TestGetValidators(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, promQuery, r.URL.Query()["query"][0])
		require.Equal(t, "Bearer test", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(fixture))
	}))
	defer ts.Close()

	vals, err := getValidators(context.Background(), ts.URL, "test")
	assert.NoError(t, err)
	testutil.RequireGoldenJSON(t, vals)
}

const fixture = `
{
  "status": "success",
  "isPartial": false,
  "data": {
    "resultType": "vector",
    "result": [
      {
        "metric": {
          "cluster_hash": "hash1",
          "cluster_name": "cluster1",
          "cluster_network": "network1",
          "pubkey_full": "0x96c85da36a35123aa17ace6588e56e948b1f7fe320f53163015f144541b65645a7aa4df44e5638a00467aff16666629c"
        },
        "value": [
          1671108542,
          "1"
        ]
      },
      {
        "metric": {
          "cluster_hash": "hash2",
          "cluster_name": "cluster2",
          "cluster_network": "network2",
          "pubkey_full": "0x800a9a1c9f6cd9fbe30a3759070646bc8bf17a1da26bbcd5b72c696396ec2dd40265fd7174231dffe9f19cfc6e64df54"
        },
        "value": [
          1671108542,
          "1"
        ]
      }
	  ]
  }
}`
