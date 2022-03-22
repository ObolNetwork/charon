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

package validatorapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"strings"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2mock "github.com/attestantio/go-eth2-client/mock"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
)

const (
	slotsPerEpoch = 32
	infoLevel     = 1 // 1 is InfoLevel, this avoids importing zerolog directly.
)

func TestRouterIntegration(t *testing.T) {
	beaconURL, ok := os.LookupEnv("BEACON_URL")
	if !ok {
		t.Skip("Skipping integration test since BEACON_URL not found")
	}

	r, err := NewRouter(Handler(nil), beaconURL)
	require.NoError(t, err)

	server := httptest.NewServer(r)
	defer server.Close()

	resp, err := http.Get(server.URL + "/eth/v1/node/version")
	require.NoError(t, err)

	require.Equal(t, 200, resp.StatusCode)
}

func TestRawRouter(t *testing.T) {
	t.Run("proxy", func(t *testing.T) {
		handler := testHandler{
			ProxyHandler: func(w http.ResponseWriter, r *http.Request) {
				b, err := httputil.DumpRequest(r, false)
				require.NoError(t, err)
				_, _ = w.Write(b)
			},
		}

		callback := func(ctx context.Context, baseURL string) {
			res, err := http.Get(baseURL + "/foo?bar=123")
			require.NoError(t, err)
			body, err := io.ReadAll(res.Body)
			require.NoError(t, err)
			require.Contains(t, string(body), "GET /foo?bar=123")
		}

		testRawRouter(t, handler, callback)
	})

	t.Run("invalid path param", func(t *testing.T) {
		handler := testHandler{}

		callback := func(ctx context.Context, baseURL string) {
			res, err := http.Get(baseURL + "/eth/v1/validator/duties/attester/not_a_number")
			require.NoError(t, err)

			var errRes errorResponse
			err = json.NewDecoder(res.Body).Decode(&errRes)
			require.NoError(t, err)
			require.Equal(t, errRes, errorResponse{
				Code:    http.StatusBadRequest,
				Message: "invalid uint path parameter epoch [not_a_number]",
			})
		}

		testRawRouter(t, handler, callback)
	})

	t.Run("empty body", func(t *testing.T) {
		handler := testHandler{}

		callback := func(ctx context.Context, baseURL string) {
			res, err := http.Get(baseURL + "/eth/v1/validator/duties/attester/1")
			require.NoError(t, err)

			var errRes errorResponse
			err = json.NewDecoder(res.Body).Decode(&errRes)
			require.NoError(t, err)
			require.Equal(t, errRes, errorResponse{
				Code:    http.StatusBadRequest,
				Message: "empty request body",
			})
		}

		testRawRouter(t, handler, callback)
	})

	t.Run("invalid request body", func(t *testing.T) {
		handler := testHandler{}

		callback := func(ctx context.Context, baseURL string) {
			res, err := http.Post(baseURL+"/eth/v1/validator/duties/attester/1", "", strings.NewReader("not json"))
			require.NoError(t, err)

			var errRes errorResponse
			err = json.NewDecoder(res.Body).Decode(&errRes)
			require.NoError(t, err)
			require.Equal(t, errRes, errorResponse{
				Code:    http.StatusBadRequest,
				Message: "failed parsing request body",
			})
		}

		testRawRouter(t, handler, callback)
	})

	t.Run("get_single_validators", func(t *testing.T) {
		handler := testHandler{
			ValidatorsFunc: func(_ context.Context, stateID string, indices []eth2p0.ValidatorIndex) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
				res := make(map[eth2p0.ValidatorIndex]*eth2v1.Validator)
				for _, index := range indices {
					res[index] = &eth2v1.Validator{
						Index:  index,
						Status: eth2v1.ValidatorStateActiveOngoing,
						Validator: &eth2p0.Validator{
							PublicKey:             testutil.RandomBLSPubKey(t),
							WithdrawalCredentials: []byte("12345678901234567890123456789012"),
						},
					}
				}

				return res, nil
			},
		}

		callback := func(ctx context.Context, baseURL string) {
			res, err := http.Get(baseURL + "/eth/v1/beacon/states/head/validators/12")
			require.NoError(t, err)

			resp := struct {
				Data *eth2v1.Validator `json:"data"`
			}{}
			err = json.NewDecoder(res.Body).Decode(&resp)
			require.NoError(t, err)
			require.EqualValues(t, 12, resp.Data.Index)
		}

		testRawRouter(t, handler, callback)
	})
}

func TestRouter(t *testing.T) {
	t.Run("attesterduty", func(t *testing.T) {
		handler := testHandler{
			AttesterDutiesFunc: func(ctx context.Context, epoch eth2p0.Epoch, il []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
				var res []*eth2v1.AttesterDuty
				for _, index := range il {
					res = append(res, &eth2v1.AttesterDuty{
						ValidatorIndex:   index,              // Echo index
						Slot:             eth2p0.Slot(epoch), // Echo epoch as slot
						CommitteeLength:  1,                  // 0 fails validation
						CommitteesAtSlot: 1,                  // 0 fails validation
					})
				}

				return res, nil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			const slotEpoch = 1
			const index0 = 2
			const index1 = 3
			res, err := cl.AttesterDuties(ctx, eth2p0.Epoch(slotEpoch), []eth2p0.ValidatorIndex{
				eth2p0.ValidatorIndex(index0),
				eth2p0.ValidatorIndex(index1),
			})
			require.NoError(t, err)

			require.Len(t, res, 2)
			require.Equal(t, int(res[0].Slot), slotEpoch)
			require.Equal(t, int(res[0].ValidatorIndex), index0)
			require.Equal(t, int(res[1].Slot), slotEpoch)
			require.Equal(t, int(res[1].ValidatorIndex), index1)
		}

		testRouter(t, handler, callback)
	})

	t.Run("proposerduty", func(t *testing.T) {
		const total = 2
		handler := testHandler{
			ProposerDutiesFunc: func(ctx context.Context, epoch eth2p0.Epoch, _ []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
				// Returns ordered total number of duties for the epoch
				var res []*eth2v1.ProposerDuty
				for i := 0; i < total; i++ {
					res = append(res, &eth2v1.ProposerDuty{
						ValidatorIndex: eth2p0.ValidatorIndex(i),
						Slot:           eth2p0.Slot(int(epoch)*slotsPerEpoch + i),
					})
				}

				return res, nil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			const epoch = 4
			const validator = 1
			res, err := cl.ProposerDuties(ctx, eth2p0.Epoch(epoch), []eth2p0.ValidatorIndex{
				eth2p0.ValidatorIndex(validator), // Only request 1 of total 2 validators
			})
			require.NoError(t, err)

			require.Len(t, res, 1)
			require.Equal(t, int(res[0].Slot), epoch*slotsPerEpoch+validator)
			require.Equal(t, int(res[0].ValidatorIndex), validator)
		}

		testRouter(t, handler, callback)
	})

	t.Run("get_validator_index", func(t *testing.T) {
		handler := testHandler{
			ValidatorsFunc: func(_ context.Context, stateID string, indices []eth2p0.ValidatorIndex) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
				res := make(map[eth2p0.ValidatorIndex]*eth2v1.Validator)
				for _, index := range indices {
					res[index] = &eth2v1.Validator{
						Index:  index,
						Status: eth2v1.ValidatorStateActiveOngoing,
						Validator: &eth2p0.Validator{
							PublicKey:             testutil.RandomBLSPubKey(t),
							WithdrawalCredentials: []byte("12345678901234567890123456789012"),
						},
					}
				}

				return res, nil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			const (
				val1 = 1
				val2 = 2
			)
			res, err := cl.Validators(ctx, "head", []eth2p0.ValidatorIndex{
				eth2p0.ValidatorIndex(val1),
				eth2p0.ValidatorIndex(val2),
			})
			require.NoError(t, err)

			require.Len(t, res, 2)
			require.EqualValues(t, val1, res[val1].Index)
			require.EqualValues(t, eth2v1.ValidatorStateActiveOngoing, res[val1].Status)
		}

		testRouter(t, handler, callback)
	})

	t.Run("get_validator_pubkeu", func(t *testing.T) {
		var idx eth2p0.ValidatorIndex
		handler := testHandler{
			ValidatorsByPubKeyFunc: func(_ context.Context, stateID string, pubkeys []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
				res := make(map[eth2p0.ValidatorIndex]*eth2v1.Validator)
				for _, pubkey := range pubkeys {
					idx++
					res[idx] = &eth2v1.Validator{
						Index:  idx,
						Status: eth2v1.ValidatorStateActiveOngoing,
						Validator: &eth2p0.Validator{
							PublicKey:             pubkey,
							WithdrawalCredentials: []byte("12345678901234567890123456789012"),
						},
					}
				}

				return res, nil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			res, err := cl.ValidatorsByPubKey(ctx, "head", []eth2p0.BLSPubKey{
				testutil.RandomBLSPubKey(t),
				testutil.RandomBLSPubKey(t),
			})
			require.NoError(t, err)

			require.Len(t, res, 2)
			require.EqualValues(t, 1, res[1].Index)
			require.EqualValues(t, eth2v1.ValidatorStateActiveOngoing, res[1].Status)
		}

		testRouter(t, handler, callback)
	})

	t.Run("attestation_data", func(t *testing.T) {
		handler := testHandler{
			AttestationDataFunc: func(ctx context.Context, slot eth2p0.Slot, commIdx eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error) {
				data := testutil.RandomAttestationData()
				data.Slot = slot
				data.Index = commIdx

				return data, nil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			const slot, commIdx = 12, 23
			res, err := cl.AttestationData(ctx, slot, commIdx)
			require.NoError(t, err)

			require.EqualValues(t, slot, res.Slot)
			require.EqualValues(t, commIdx, res.Index)
		}

		testRouter(t, handler, callback)
	})
}

// testRouter is a helper function to test router endpoints with an eth2http client. The outer test
// provides the mocked test handler and a callback that does the client side test.
func testRouter(t *testing.T, handler testHandler, callback func(context.Context, *eth2http.Service)) {
	t.Helper()
	proxy := httptest.NewServer(handler.newBeaconHandler(t))
	defer proxy.Close()

	r, err := NewRouter(handler, proxy.URL)
	require.NoError(t, err)

	server := httptest.NewServer(r)
	defer server.Close()

	ctx := context.Background()

	cl, err := eth2http.New(ctx, eth2http.WithAddress(server.URL), eth2http.WithLogLevel(infoLevel))
	require.NoError(t, err)

	callback(ctx, cl.(*eth2http.Service))
}

// testRawRouter is a helper function to test router endpoints with a raw http client. The outer test
// provides the mocked test handler and a callback that does the client side test.
func testRawRouter(t *testing.T, handler testHandler, callback func(context.Context, string)) {
	t.Helper()
	proxy := httptest.NewServer(handler.newBeaconHandler(t))
	defer proxy.Close()

	r, err := NewRouter(handler, proxy.URL)
	require.NoError(t, err)

	server := httptest.NewServer(r)
	defer server.Close()

	callback(context.Background(), server.URL)
}

// testHandler implements the Handler interface allowing test-cases to specify only what they require.
// This includes optional validatorapi handler functions, an optional beacon-node reserve proxy handler, and
// mocked beacon-node endpoints required by the eth2http client during startup.
type testHandler struct {
	Handler
	ProxyHandler           http.HandlerFunc
	AttestationDataFunc    func(ctx context.Context, slot eth2p0.Slot, commIdx eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error)
	AttesterDutiesFunc     func(ctx context.Context, epoch eth2p0.Epoch, il []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error)
	ProposerDutiesFunc     func(ctx context.Context, epoch eth2p0.Epoch, il []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error)
	ValidatorsFunc         func(ctx context.Context, stateID string, indices []eth2p0.ValidatorIndex) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error)
	ValidatorsByPubKeyFunc func(ctx context.Context, stateID string, pubkeys []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error)
}

func (h testHandler) AttestationData(ctx context.Context, slot eth2p0.Slot, commIdx eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error) {
	return h.AttestationDataFunc(ctx, slot, commIdx)
}

func (h testHandler) AttesterDuties(ctx context.Context, epoch eth2p0.Epoch, il []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
	return h.AttesterDutiesFunc(ctx, epoch, il)
}

func (h testHandler) Validators(ctx context.Context, stateID string, indices []eth2p0.ValidatorIndex) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
	return h.ValidatorsFunc(ctx, stateID, indices)
}

func (h testHandler) ValidatorsByPubKey(ctx context.Context, stateID string, pubkeys []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
	return h.ValidatorsByPubKeyFunc(ctx, stateID, pubkeys)
}

func (h testHandler) ProposerDuties(ctx context.Context, epoch eth2p0.Epoch, il []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
	return h.ProposerDutiesFunc(ctx, epoch, il)
}

// newBeaconHandler returns a mock beacon node handler. It registers a few mock handlers required by the
// eth2http service on startup, all other requests are routed to ProxyHandler if not nil.
func (h testHandler) newBeaconHandler(t *testing.T) http.Handler {
	t.Helper()
	ctx := context.Background()
	mock, err := eth2mock.New(ctx, eth2mock.WithLogLevel(infoLevel))
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/eth/v1/beacon/genesis", func(w http.ResponseWriter, r *http.Request) {
		res, err := mock.Genesis(ctx)
		require.NoError(t, err)
		writeResponse(ctx, w, "", res)
	})
	mux.HandleFunc("/eth/v1/config/spec", func(w http.ResponseWriter, r *http.Request) {
		res := map[string]interface{}{
			"SLOTS_PER_EPOCH": fmt.Sprint(slotsPerEpoch),
		}
		writeResponse(ctx, w, "", nest(res, "data"))
	})
	mux.HandleFunc("/eth/v1/config/deposit_contract", func(w http.ResponseWriter, r *http.Request) {
		res, err := mock.DepositContract(ctx)
		require.NoError(t, err)
		writeResponse(ctx, w, "", res)
	})
	mux.HandleFunc("/eth/v1/config/fork_schedule", func(w http.ResponseWriter, r *http.Request) {
		res, err := mock.ForkSchedule(ctx)
		require.NoError(t, err)
		writeResponse(ctx, w, "", nest(res, "data"))
	})
	mux.HandleFunc("/eth/v1/node/version", func(w http.ResponseWriter, r *http.Request) {
		res, err := mock.NodeVersion(ctx)
		require.NoError(t, err)
		writeResponse(ctx, w, "", nest(res, "version", "data"))
	})

	if h.ProxyHandler != nil {
		mux.HandleFunc("/", h.ProxyHandler)
	}

	return mux
}

// nest returns a json nested version the data objected. Note nests must be provided in inverse order.
func nest(data interface{}, nests ...string) interface{} {
	res := data

	for _, nest := range nests {
		res = map[string]interface{}{
			nest: res,
		}
	}

	return res
}
