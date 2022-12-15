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

// getValidationStatistics queries rated for a pubkey and returns rated data about the pubkey
func getValidationStatistics(ctx context.Context, ratedEndpoint string, validator validator) (*validatorEffectivenessData, error) {
	url, err := url.Parse(ratedEndpoint)
	if err != nil {
		return nil, errors.Wrap(err, "parse rated endpoint")
	}

	url.Path = fmt.Sprintf("/v0/eth/validators/%s/effectiveness", validator.PubKey)

	query := url.Query()
	query.Add("size", "1")
	url.RawQuery = query.Encode()

	maxRetries := 10

	client := new(http.Client)

	for r := 0; r <= maxRetries; r++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
		if err != nil {
			return nil, errors.Wrap(err, "new rated request")
		}

		//Workaround for rated api not recognising goerli
		clusterNetwork := validator.ClusterNetwork
		if clusterNetwork == "goerli" {
			clusterNetwork = "prater"
		}

		req.Header.Add("X-Rated-Network", clusterNetwork)
		res, err := client.Do(req)
		if err != nil {
			return nil, errors.Wrap(err, "requesting rated matrics")
		}

		bodyFunc := func() ([]byte, error) {
			body, err := io.ReadAll(res.Body)
			if err != nil {
				return nil, errors.Wrap(err, "reading body")
			}

			defer res.Body.Close()

			return body, nil
		}

		body, err := bodyFunc()
		if err != nil {
			return nil, err
		}

		if res.StatusCode == 429 {
			sleepFor := expbackoff.Backoff(expbackoff.DefaultConfig, r)
			log.Info(ctx, fmt.Sprintln("Rate limit exceeded. Retrying after .", sleepFor))
			time.Sleep(sleepFor)

			continue
		} else if res.StatusCode/100 != 2 {
			return nil, errors.New("not ok http response", z.Str("body", string(body)))
		}

		return parseMetrics(body)
	}

	return nil, errors.New("fetching Validator data", z.Int("retries", maxRetries))
}

// parseMetrics reads rated response and returns the validator effectiveness data
func parseMetrics(body []byte) (*validatorEffectivenessData, error) {
	var result struct {
		Data []validatorEffectivenessData `json:"data"`
	}

	err := json.Unmarshal(body, &result)
	if err != nil {
		return nil, errors.Wrap(err, "deserializing json")
	}

	if len(result.Data) != 1 {
		return nil, errors.New("unexpected data response from rated network")
	}

	return &result.Data[0], nil
}
