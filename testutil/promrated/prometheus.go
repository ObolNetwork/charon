// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package promrated

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

const (
	promQuery = "group by (cluster_name, cluster_hash, cluster_network, pubkey_full) (core_scheduler_validator_balance_gwei)"
)

type validator struct {
	PubKey         string `json:"pubkey_full"`
	ClusterName    string `json:"cluster_name"`
	ClusterHash    string `json:"cluster_hash"`
	ClusterNetwork string `json:"cluster_network"`
}

// serveMonitoring creates a liveness endpoint and serves metrics to prometheus.
func serveMonitoring(addr string, registry *prometheus.Registry) error {
	mux := http.NewServeMux()

	mux.Handle("/livez", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeResponse(w, http.StatusOK, "ok")
	}))

	mux.Handle("/metrics", promhttp.InstrumentMetricHandler(
		registry, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}),
	))

	server := http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: time.Second,
	}

	return errors.Wrap(server.ListenAndServe(), "failed to serve prometheus metrics")
}

// getValidators queries prometheus and returns a list of validators with associated cluster and pubkey.
func getValidators(ctx context.Context, promEndpoint string, promAuth string) ([]validator, error) {
	client := new(http.Client)

	url, err := url.ParseRequestURI(promEndpoint)
	if err != nil {
		return nil, errors.Wrap(err, "parse prometheus endpoint")
	}

	query := url.Query()
	query.Add("query", promQuery)
	url.RawQuery = query.Encode()

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

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "reading body")
	}

	if res.StatusCode/100 != 2 {
		return nil, errors.New("not ok http response", z.Str("body", string(body)))
	}

	return parseValidators(body)
}

// parseValidators reads prometheus response and returns a list of validators.
func parseValidators(body []byte) ([]validator, error) {
	var result struct {
		Data struct {
			Result []struct {
				Labels validator `json:"metric"`
			} `json:"result"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, errors.Wrap(err, "deserializing json")
	}

	var validators []validator
	for _, datum := range result.Data.Result {
		if datum.Labels.ClusterName == "" || datum.Labels.ClusterNetwork == "" || datum.Labels.PubKey == "" {
			continue
		}
		validators = append(validators, datum.Labels)
	}

	return validators, nil
}

func writeResponse(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}
