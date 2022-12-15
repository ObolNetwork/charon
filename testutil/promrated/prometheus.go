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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

const (
	promQuery = "group by (cluster_name, cluster_hash, cluster_peer, pubkey_full) (core_scheduler_validator_balance_gwei)"
)

type validator struct {
	PubKey         string `json:"pubkey_full"`
	ClusterName    string `json:"cluster_name"`
	ClusterHash    string `json:"cluster_hash"`
	ClusterNetwork string `json:"cluster_network"`
	ClusterPeer    string `json:"cluster_peer"`
}

type promMetric struct {
	validator
}

type promResult struct {
	Metric promMetric `json:"metric"`
}

type promData struct {
	Result []promResult `json:"result"`
}

type promResponse struct {
	Data promData `json:"data"`
}

// serveMonitoring creates a liveness endpoint and serves metrics to prometheus.
func serveMonitoring(addr string) error {
	mux := http.NewServeMux()

	mux.Handle("/livez", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeResponse(w, http.StatusOK, "ok")
	}))

	mux.Handle("/metrics",
		promhttp.Handler(),
	)

	server := http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: time.Second}

	return errors.Wrap(server.ListenAndServe(), "failed to serve prometheus metrics")
}

// getValidators queries prometheus and returns a list of validators with associated cluster and pubkey
func getValidators(ctx context.Context, promEndpoint string, promAuth string) ([]validator, error) {
	client := new(http.Client)

	url, err := url.Parse(promEndpoint)

	query := url.Query()
	query.Add("query", "group by (cluster_name, cluster_hash, cluster_peer, pubkey_full) (core_scheduler_validator_balance_gwei)")
	url.RawQuery = query.Encode()

	if err != nil {
		return nil, errors.Wrap(err, "parsing url")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "new prometheus request")
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", promAuth))
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "requesting prom metrics")
	}
	defer res.Body.Close()

	if err != nil {
		return nil, err
	}

	if res.StatusCode == 200 {
		return constructValidators(ctx, res)
	}

	return nil, errors.New("processing prom metrics", z.Str("url", url.String()))
}

// constructValidators reads prometheus response and returns a list of validators
func constructValidators(ctx context.Context, res *http.Response) ([]validator, error) {
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "reading body")
	}

	var result *promResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, errors.Wrap(err, "deserializing json")
	}

	if err != nil {
		return nil, err
	}

	validators := make([]validator, len(result.Data.Result))

	for i, cluster := range result.Data.Result {
		if cluster.Metric.validator.ClusterName != "" && cluster.Metric.PubKey != "" {
			validators[i] = cluster.Metric.validator
		}
	}

	return validators, nil
}

func writeResponse(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}
