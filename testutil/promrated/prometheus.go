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
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

const (
	promEndpoint = "https://vm.monitoring.gcp.obol.tech"
	promQuery    = "group%20by%20%28cluster_name%2C%20ccluster_hash%2C%20cluster_peer%2C%20cluster_network%2C%20pubkey_full%29%20%28core_scheduler_validator_balance_gwei%29"
)

type ClusterInfo struct {
	ClusterName    string `json:"cluster_name"`
	ClusterHash    string `json:"cluster_hash"`
	ClusterNetwork string `json:"cluster_network"`
	ClusterPeer    string `json:"cluster_peer"`
}

type PromMetric struct {
	*ClusterInfo
	PubKey string `json:"pubkey_full"`
}

type PromResult struct {
	Metric PromMetric `json:"metric"`
}

type PromData struct {
	ResultType string       `json:"resultType"`
	Result     []PromResult `json:"result"`
}

type PromResponse struct {
	Status    string `json:"status"`
	IsPartial bool   `json:"isPartial"`

	Data PromData `json:"data"`
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

func getPubkeyToClusterInfo(ctx context.Context, promAuth string) (map[string]prometheus.Labels, error) {
	res, err := getPromClusters(ctx, promAuth)
	if err != nil {
		return nil, err
	}

	if res.StatusCode == 200 {
		result, err := readPromJson(ctx, res)
		if err != nil {
			return nil, err
		}

		keyToClusterLabels := make(map[string]prometheus.Labels)

		for _, cluster := range result.Data.Result {
			if cluster.Metric.ClusterInfo != nil && cluster.Metric.ClusterName != "" {
				keyToClusterLabels[cluster.Metric.PubKey] = map[string]string{
					"cluster_name":    cluster.Metric.ClusterName,
					"cluster_hash":    cluster.Metric.ClusterHash,
					"cluster_network": cluster.Metric.ClusterNetwork,
					"cluster_peer":    cluster.Metric.ClusterPeer,
					"pubkey":          cluster.Metric.PubKey,
				}
			}
		}

		return keyToClusterLabels, nil
	}

	return nil, errors.New("error processing prom metrics", z.Str("url", res.Request.RequestURI))
}

func getPromClusters(ctx context.Context, promAuth string) (*http.Response, error) {
	client := new(http.Client)
	url := fmt.Sprintf("%s/query?query=%s", promEndpoint, promQuery)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		log.Error(ctx, "HTTP Request malformed for prom query", err)
		return nil, errors.Wrap(err, "error creating prom metrics query")
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", promAuth))
	res, err := client.Do(req)
	if err != nil {
		log.Error(ctx, "HTTP Request failed for prom query", err)
		return nil, errors.Wrap(err, "error requesting prom metrics")
	}

	return res, nil
}

func readPromJson(ctx context.Context, res *http.Response) (*PromResponse, error) {
	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Error(ctx, "Failed to read body", err)
		return nil, errors.Wrap(err, "failed to read body")
	}

	var result *PromResponse
	if err := json.Unmarshal(body, &result); err != nil {
		log.Error(ctx, "Failed to deserialize json", err)
	}

	return result, nil
}

func writeResponse(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}
