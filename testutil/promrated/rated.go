// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package promrated

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/expbackoff"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

type validatorEffectivenessData struct {
	Uptime                 float64 `json:"uptime"`
	AvgCorrectness         float64 `json:"avgCorrectness"`
	AvgInclusionDelay      float64 `json:"avgInclusionDelay"`
	AttesterEffectiveness  float64 `json:"attesterEffectiveness"`
	ProposerEffectiveness  float64 `json:"proposerEffectiveness"`
	ValidatorEffectiveness float64 `json:"validatorEffectiveness"`
}

type networkEffectivenessData struct {
	AvgUptime              float64 `json:"avgUptime"`
	AvgCorrectness         float64 `json:"avgCorrectness"`
	AvgInclusionDelay      float64 `json:"avgInclusionDelay"`
	ValidatorEffectiveness float64 `json:"avgValidatorEffectiveness"`
}

// getValidatorStatistics queries rated for a pubkey and returns rated data about the pubkey
// See https://api.rated.network/docs#/default/get_effectiveness_v0_eth_validators__validator_index_or_pubkey__effectiveness_get
func getValidatorStatistics(ctx context.Context, ratedEndpoint string, ratedAuth string, validator validator) (validatorEffectivenessData, error) {
	url, err := url.Parse(ratedEndpoint)
	if err != nil {
		return validatorEffectivenessData{}, errors.Wrap(err, "parse rated endpoint")
	}

	url.Path = fmt.Sprintf("/v0/eth/validators/%s/effectiveness", validator.PubKey)

	// Adding size=1 will get only the latest day of data
	query := url.Query()
	query.Add("size", "1")
	url.RawQuery = query.Encode()

	body, err := queryRatedAPI(ctx, url, ratedAuth, validator.ClusterNetwork)
	if err != nil {
		return validatorEffectivenessData{}, err
	}

	return parseValidatorMetrics(body)
}

// getNetworkStatistics queries rated for the network and returns the network 1d average
// See https://api.rated.network/docs#/Network/get_network_overview_v0_eth_network_overview_get
func getNetworkStatistics(ctx context.Context, ratedEndpoint string, ratedAuth string, network string) (networkEffectivenessData, error) {
	url, err := url.Parse(ratedEndpoint)
	if err != nil {
		return networkEffectivenessData{}, errors.Wrap(err, "parse rated endpoint")
	}

	url.Path = "/v0/eth/network/stats"

	body, err := queryRatedAPI(ctx, url, ratedAuth, network)
	if err != nil {
		return networkEffectivenessData{}, err
	}

	return parseNetworkMetrics(body)
}

// queryRatedAPI queries rated url and returns effectiveness data.
func queryRatedAPI(ctx context.Context, url *url.URL, ratedAuth string, network string) ([]byte, error) {
	// Workaround for rated api not recognising goerli
	clusterNetwork := network
	if clusterNetwork == "goerli" {
		clusterNetwork = "prater"
	}

	maxRetries := 10

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	client := new(http.Client)
	backoff := expbackoff.New(ctx)

	for r := 0; r <= maxRetries; r++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
		if err != nil {
			return nil, errors.Wrap(err, "new rated request")
		}

		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", ratedAuth))
		req.Header.Add("X-Rated-Network", clusterNetwork)
		res, err := client.Do(req)
		if err != nil {
			return nil, errors.Wrap(err, "requesting rated matrics")
		}

		body, err := extractBody(res)
		if err != nil {
			return nil, err
		}

		if res.StatusCode == http.StatusTooManyRequests {
			log.Info(ctx, "Rate limit exceeded", z.Int("retry", r))
			backoff()

			continue
		} else if res.StatusCode/100 != 2 {
			incRatedErrors(res.StatusCode)

			return nil, errors.New("not ok http response", z.Str("body", string(body)))
		}

		return body, nil
	}

	return nil, errors.New("max retries exceeded fetching validator data", z.Int("max", maxRetries))
}

// parseValidatorMetrics reads the validator rated response and returns the validator effectiveness data.
func parseValidatorMetrics(body []byte) (validatorEffectivenessData, error) {
	var result struct {
		Data []validatorEffectivenessData `json:"data"`
	}

	err := json.Unmarshal(body, &result)
	if err != nil {
		return validatorEffectivenessData{}, errors.Wrap(err, "deserializing json")
	}

	if len(result.Data) != 1 {
		return validatorEffectivenessData{}, errors.New("unexpected data response from rated network")
	}

	return result.Data[0], nil
}

// parseNetworkMetrics reads the network rated response and returns the network effectiveness data.
func parseNetworkMetrics(body []byte) (networkEffectivenessData, error) {
	var result []networkEffectivenessData

	err := json.Unmarshal(body, &result)
	if err != nil {
		return networkEffectivenessData{}, errors.Wrap(err, "deserializing json")
	}

	if len(result) == 0 {
		return networkEffectivenessData{}, errors.New("unexpected data response from rated network")
	}

	return result[0], nil
}

func extractBody(res *http.Response) ([]byte, error) {
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "reading body")
	}

	defer res.Body.Close()

	return body, nil
}

func incRatedErrors(statusCode int) {
	ratedErrors.WithLabelValues(strconv.Itoa(statusCode)).Inc()
}
