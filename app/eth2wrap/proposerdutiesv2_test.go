// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/testutil"
)

func TestProposerDutiesV2(t *testing.T) {
	depRoot := testutil.RandomRoot()
	pubkey := testutil.RandomEth2PubKey(t)

	const (
		epoch  = 7
		header = "Authorization"
		token  = "Bearer test"
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, fmt.Sprintf("/eth/v2/validator/duties/proposer/%d", epoch), r.URL.Path)
		require.Equal(t, token, r.Header.Get(header))

		_, _ = fmt.Fprintf(w, `{
			"dependent_root": "%#x",
			"execution_optimistic": true,
			"data": [{"pubkey": "%#x", "validator_index": "2", "slot": "224"}]
		}`, depRoot, pubkey)
	}))
	defer srv.Close()

	client := eth2wrap.NewHTTPAdapterForT(t, srv.URL, map[string]string{header: token}, time.Second)

	resp, err := client.ProposerDutiesV2(t.Context(), eth2p0.Epoch(epoch))
	require.NoError(t, err)
	require.Equal(t, depRoot, resp.DependentRoot)
	require.True(t, resp.ExecutionOptimistic)
	require.Len(t, resp.Duties, 1)
	require.Equal(t, pubkey, resp.Duties[0].PubKey)
	require.Equal(t, eth2p0.ValidatorIndex(2), resp.Duties[0].ValidatorIndex)
	require.Equal(t, eth2p0.Slot(224), resp.Duties[0].Slot)
}

func TestProposerDutiesV2Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := eth2wrap.NewHTTPAdapterForT(t, srv.URL, nil, time.Second)

	_, err := client.ProposerDutiesV2(t.Context(), 1)
	require.ErrorContains(t, err, "get proposer duties v2 failed")
}
