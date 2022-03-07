// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package beaconmock

import (
	"context"
	_ "embed"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2http "github.com/attestantio/go-eth2-client/http"

	"github.com/obolnetwork/charon/app/errors"
)

//go:embed static.json
var staticJSON []byte

// StaticProvider defines a subset of eth2 service providers that
// are served from memory after fetching the data once on startup.
type StaticProvider interface {
	eth2client.DepositContractProvider
	eth2client.DomainProvider
	eth2client.ForkProvider
	eth2client.ForkScheduleProvider
	eth2client.GenesisProvider
	eth2client.GenesisTimeProvider
	eth2client.NodeVersionProvider
	eth2client.SlotDurationProvider
	eth2client.SlotsPerEpochProvider
	eth2client.SpecProvider
	// Above sorted alphabetically
}

// NewStaticProvider returns eth2 http client that is populated with static values defined in static.json.
func NewStaticProvider(ctx context.Context) (StaticProvider, error) {
	respPerPath := make(map[string]json.RawMessage)
	err := json.Unmarshal(staticJSON, &respPerPath)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal static json")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(respPerPath[r.URL.Path])
	}))
	defer srv.Close()

	ethCl, err := eth2http.New(ctx, eth2http.WithAddress(srv.URL), eth2http.WithLogLevel(1))
	if err != nil {
		return nil, errors.Wrap(err, "new eth2 http")
	}

	return ethCl.(StaticProvider), nil
}
