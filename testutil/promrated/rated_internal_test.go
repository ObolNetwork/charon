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

func TestGetNodeOperatorStatistics(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v0/eth/operators/Lido/effectiveness", r.URL.Path)

		require.Equal(t, "Bearer auth", r.Header.Get("Authorization"))
		require.Equal(t, "prater", r.Header.Get("X-Rated-Network"))
		_, _ = w.Write([]byte(ratedNodeOperatorFixture))
	}))
	defer ts.Close()

	vals, err := getNodeOperatorStatistics(context.Background(), ts.URL, "auth", "Lido", "goerli")
	assert.NoError(t, err)
	testutil.RequireGoldenJSON(t, vals)
}

const ratedNetworkFixture = `
[
    {
        "avgUptime": 0.9964608763093223,
        "avgInclusionDelay": 1.0147019732112206,
        "avgCorrectness": 0.982182918384125,
        "avgValidatorEffectiveness": 45.6838307968488,
        "avgProposerEffectiveness": 12.68383072342342,
        "avgAttesterEffectiveness": 67.2343240993498
    }
]`

const ratedNodeOperatorFixture = `
{
	"data": [
    	{
			"avgUptime": 0.352353432111,
			"avgInclusionDelay": 1.0147019732112206,
			"avgCorrectness": 0.3452333554125,
			"avgValidatorEffectiveness": 45.6838307968488,
			"avgProposerEffectiveness": 54.68383072342342,
			"avgAttesterEffectiveness": 21.2343240993498
    	}
	]
}`
