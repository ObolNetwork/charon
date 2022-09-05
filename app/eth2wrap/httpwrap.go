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

package eth2wrap

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	eth2http "github.com/attestantio/go-eth2-client/http"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
)

// httpAdapter implements Client by wrapping eth2http.Service adding the experimental
// interfaces not present go-eth2-client.
type httpAdapter struct {
	*eth2http.Service
}

type submitBeaconCommitteeSubscriptionsV2JSON struct {
	Data []*eth2exp.BeaconCommitteeSubscriptionResponse `json:"data"`
}

// SubmitBeaconCommitteeSubscriptionsV2 implements eth2exp.BeaconCommitteeSubscriptionsSubmitterV2.
func (h httpAdapter) SubmitBeaconCommitteeSubscriptionsV2(ctx context.Context, subscriptions []*eth2exp.BeaconCommitteeSubscription) ([]*eth2exp.BeaconCommitteeSubscriptionResponse, error) {
	reqBody, err := json.Marshal(subscriptions)
	if err != nil {
		return nil, errors.Wrap(err, "marshal submit beacon committee subscriptions V2 request")
	}

	respBody, err := httpPost(ctx, h.Address(), "/eth/v2/validator/beacon_committee_subscriptions", bytes.NewReader(reqBody))
	if err != nil {
		return nil, errors.Wrap(err, "post submit beacon committee subscriptions v2")
	}

	var resp submitBeaconCommitteeSubscriptionsV2JSON
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, errors.Wrap(err, "failed to parse submit beacon committee subscriptions V2 response")
	}

	return resp.Data, nil
}

func httpPost(ctx context.Context, base string, endpoint string, body io.Reader) ([]byte, error) {
	addr, err := url.JoinPath(base, endpoint)
	if err != nil {
		return nil, errors.Wrap(err, "invalid address")
	}

	url, err := url.Parse(addr)
	if err != nil {
		return nil, errors.Wrap(err, "invalid endpoint")
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second*2) // TODO(dhruv): use actual configured timeout.
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), body)
	if err != nil {
		return nil, errors.Wrap(err, "new POST request with ctx")
	}

	res, err := new(http.Client).Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to call POST endpoint")
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read GET response")
	}

	if res.StatusCode/100 != 2 {
		return nil, errors.New("get failed", z.Int("status", res.StatusCode), z.Str("body", string(data)))
	}

	return data, nil
}
