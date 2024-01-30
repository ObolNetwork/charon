// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

func TestGetValidatorStatistics(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v0/eth/validators/0xA/effectiveness", r.URL.Path)
		require.Equal(t, "1", r.URL.Query()["size"][0])

		require.Equal(t, "Bearer auth", r.Header.Get("Authorization"))
		require.Equal(t, "prater", r.Header.Get("X-Rated-Network"))
		_, _ = w.Write([]byte(ratedValidatorFixture))
	}))
	defer ts.Close()

	validator := validator{ClusterName: "test-cluster", ClusterHash: "hash", ClusterNetwork: "goerli", PubKey: "0xA"}

	vals, err := getValidatorStatistics(context.Background(), ts.URL, "auth", validator)
	assert.NoError(t, err)
	testutil.RequireGoldenJSON(t, vals)
}

func TestGetNetworkStatistics(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v0/eth/network/stats", r.URL.Path)

		require.Equal(t, "Bearer auth", r.Header.Get("Authorization"))
		require.Equal(t, "prater", r.Header.Get("X-Rated-Network"))
		_, _ = w.Write([]byte(ratedNetworkFixture))
	}))
	defer ts.Close()

	vals, err := getNetworkStatistics(context.Background(), ts.URL, "auth", "goerli")
	assert.NoError(t, err)
	testutil.RequireGoldenJSON(t, vals)
}

const ratedValidatorFixture = `
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

const ratedNetworkFixture = `
[
    {
        "avgUptime": 0.9964608763093223,
        "avgInclusionDelay": 1.0147019732112206,
        "avgCorrectness": 0.9914412918384125,
        "avgValidatorEffectiveness": 97.6838307968488
    }
]`
