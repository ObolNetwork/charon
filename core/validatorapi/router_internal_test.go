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

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2mock "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
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

	r, err := NewRouter(Handler(nil), testBeaconAddr(beaconURL))
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

	t.Run("client timeout", func(t *testing.T) {
		cctx, cancel := context.WithCancel(context.Background())
		handler := testHandler{
			ValidatorsFunc: func(sctx context.Context, stateID string, indices []eth2p0.ValidatorIndex) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
				cancel()      // Ensure that cancelling client context (cctx)
				<-sctx.Done() // Results in server context (sctx) being closed.

				return nil, sctx.Err()
			},
		}

		callback := func(_ context.Context, baseURL string) {
			req, err := http.NewRequestWithContext(cctx, "GET", baseURL+"/eth/v1/beacon/states/head/validators/12", nil)
			require.NoError(t, err)

			_, err = new(http.Client).Do(req)
			if !errors.Is(err, context.Canceled) {
				require.NoError(t, err)
			}
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
							PublicKey:             testutil.RandomEth2PubKey(t),
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

//nolint:maintidx // This function a test of tests, so analyses as "complex".
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
							PublicKey:             testutil.RandomEth2PubKey(t),
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
				testutil.RandomEth2PubKey(t),
				testutil.RandomEth2PubKey(t),
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

	t.Run("submit_randao", func(t *testing.T) {
		handler := testHandler{
			BeaconBlockProposalFunc: func(ctx context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature, graffiti []byte) (*spec.VersionedBeaconBlock, error) {
				return nil, errors.New("not implemented")
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			slot := eth2p0.Slot(1)
			randaoReveal := testutil.RandomEth2Signature()
			graffiti := testutil.RandomBytes32()

			res, err := cl.BeaconBlockProposal(ctx, slot, randaoReveal, graffiti)
			require.Error(t, err)
			require.Nil(t, res)
		}

		testRouter(t, handler, callback)
	})

	t.Run("submit_randao_blinded_block", func(t *testing.T) {
		handler := testHandler{
			BlindedBeaconBlockProposalFunc: func(ctx context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature, graffiti []byte) (*eth2api.VersionedBlindedBeaconBlock, error) {
				return nil, errors.New("not implemented")
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			slot := eth2p0.Slot(1)
			randaoReveal := testutil.RandomEth2Signature()
			graffiti := testutil.RandomBytes32()

			res, err := cl.BlindedBeaconBlockProposal(ctx, slot, randaoReveal, graffiti)
			require.Error(t, err)
			require.Nil(t, res)
		}

		testRouter(t, handler, callback)
	})

	t.Run("submit_block_phase0", func(t *testing.T) {
		block1 := &spec.VersionedSignedBeaconBlock{
			Version: spec.DataVersionPhase0,
			Phase0: &eth2p0.SignedBeaconBlock{
				Message:   testutil.RandomPhase0BeaconBlock(),
				Signature: testutil.RandomEth2Signature(),
			},
		}
		handler := testHandler{
			SubmitBeaconBlockFunc: func(ctx context.Context, block *spec.VersionedSignedBeaconBlock) error {
				require.Equal(t, block, block1)
				return nil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			err := cl.SubmitBeaconBlock(ctx, block1)
			require.NoError(t, err)
		}

		testRouter(t, handler, callback)
	})

	t.Run("submit_block_altair", func(t *testing.T) {
		block1 := &spec.VersionedSignedBeaconBlock{
			Version: spec.DataVersionAltair,
			Altair: &altair.SignedBeaconBlock{
				Message:   testutil.RandomAltairBeaconBlock(t),
				Signature: testutil.RandomEth2Signature(),
			},
		}
		handler := testHandler{
			SubmitBeaconBlockFunc: func(ctx context.Context, block *spec.VersionedSignedBeaconBlock) error {
				require.Equal(t, block, block1)
				return nil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			err := cl.SubmitBeaconBlock(ctx, block1)
			require.NoError(t, err)
		}

		testRouter(t, handler, callback)
	})

	t.Run("submit_block_bellatrix", func(t *testing.T) {
		block1 := &spec.VersionedSignedBeaconBlock{
			Version: spec.DataVersionBellatrix,
			Bellatrix: &bellatrix.SignedBeaconBlock{
				Message:   testutil.RandomBellatrixBeaconBlock(t),
				Signature: testutil.RandomEth2Signature(),
			},
		}
		handler := testHandler{
			SubmitBeaconBlockFunc: func(ctx context.Context, block *spec.VersionedSignedBeaconBlock) error {
				require.Equal(t, block, block1)
				return nil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			err := cl.SubmitBeaconBlock(ctx, block1)
			require.NoError(t, err)
		}

		testRouter(t, handler, callback)
	})

	t.Run("submit_blinded_block_bellatrix", func(t *testing.T) {
		block1 := &eth2api.VersionedSignedBlindedBeaconBlock{
			Version: spec.DataVersionBellatrix,
			Bellatrix: &eth2v1.SignedBlindedBeaconBlock{
				Message:   testutil.RandomBellatrixBlindedBeaconBlock(t),
				Signature: testutil.RandomEth2Signature(),
			},
		}
		handler := testHandler{
			SubmitBlindedBeaconBlockFunc: func(ctx context.Context, block *eth2api.VersionedSignedBlindedBeaconBlock) error {
				require.Equal(t, block, block1)
				return nil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			err := cl.SubmitBlindedBeaconBlock(ctx, block1)
			require.NoError(t, err)
		}

		testRouter(t, handler, callback)
	})

	t.Run("submit_validator_registration", func(t *testing.T) {
		expect := []*eth2api.VersionedSignedValidatorRegistration{
			{
				Version: spec.BuilderVersionV1,
				V1:      testutil.RandomSignedValidatorRegistration(t),
			},
		}
		handler := testHandler{
			SubmitValidatorRegistrationsFunc: func(ctx context.Context, actual []*eth2api.VersionedSignedValidatorRegistration) error {
				require.Equal(t, actual, expect)

				return nil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			err := cl.SubmitValidatorRegistrations(ctx, expect)
			require.NoError(t, err)
		}

		testRouter(t, handler, callback)
	})

	t.Run("submit_voluntary_exit", func(t *testing.T) {
		exit1 := testutil.RandomExit()

		handler := testHandler{
			SubmitVoluntaryExitFunc: func(ctx context.Context, exit2 *eth2p0.SignedVoluntaryExit) error {
				require.Equal(t, *exit1, *exit2)
				return nil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			err := cl.SubmitVoluntaryExit(ctx, exit1)
			require.NoError(t, err)
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

	r, err := NewRouter(handler, testBeaconAddr(proxy.URL))
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

	r, err := NewRouter(handler, testBeaconAddr(proxy.URL))
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
	ProxyHandler                     http.HandlerFunc
	AttestationDataFunc              func(ctx context.Context, slot eth2p0.Slot, commIdx eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error)
	AttesterDutiesFunc               func(ctx context.Context, epoch eth2p0.Epoch, il []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error)
	BeaconBlockProposalFunc          func(ctx context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature, graffiti []byte) (*spec.VersionedBeaconBlock, error)
	SubmitBeaconBlockFunc            func(ctx context.Context, block *spec.VersionedSignedBeaconBlock) error
	BlindedBeaconBlockProposalFunc   func(ctx context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature, graffiti []byte) (*eth2api.VersionedBlindedBeaconBlock, error)
	SubmitBlindedBeaconBlockFunc     func(ctx context.Context, block *eth2api.VersionedSignedBlindedBeaconBlock) error
	ProposerDutiesFunc               func(ctx context.Context, epoch eth2p0.Epoch, il []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error)
	ValidatorsFunc                   func(ctx context.Context, stateID string, indices []eth2p0.ValidatorIndex) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error)
	ValidatorsByPubKeyFunc           func(ctx context.Context, stateID string, pubkeys []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error)
	SubmitVoluntaryExitFunc          func(ctx context.Context, exit *eth2p0.SignedVoluntaryExit) error
	SubmitValidatorRegistrationsFunc func(ctx context.Context, registrations []*eth2api.VersionedSignedValidatorRegistration) error
}

func (h testHandler) AttestationData(ctx context.Context, slot eth2p0.Slot, commIdx eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error) {
	return h.AttestationDataFunc(ctx, slot, commIdx)
}

func (h testHandler) AttesterDuties(ctx context.Context, epoch eth2p0.Epoch, il []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
	return h.AttesterDutiesFunc(ctx, epoch, il)
}

func (h testHandler) BeaconBlockProposal(ctx context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature, graffiti []byte) (*spec.VersionedBeaconBlock, error) {
	return h.BeaconBlockProposalFunc(ctx, slot, randaoReveal, graffiti)
}

func (h testHandler) SubmitBeaconBlock(ctx context.Context, block *spec.VersionedSignedBeaconBlock) error {
	return h.SubmitBeaconBlockFunc(ctx, block)
}

func (h testHandler) BlindedBeaconBlockProposal(ctx context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature, graffiti []byte) (*eth2api.VersionedBlindedBeaconBlock, error) {
	return h.BlindedBeaconBlockProposalFunc(ctx, slot, randaoReveal, graffiti)
}

func (h testHandler) SubmitBlindedBeaconBlock(ctx context.Context, block *eth2api.VersionedSignedBlindedBeaconBlock) error {
	return h.SubmitBlindedBeaconBlockFunc(ctx, block)
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

func (h testHandler) SubmitVoluntaryExit(ctx context.Context, exit *eth2p0.SignedVoluntaryExit) error {
	return h.SubmitVoluntaryExitFunc(ctx, exit)
}

func (h testHandler) SubmitValidatorRegistrations(ctx context.Context, registrations []*eth2api.VersionedSignedValidatorRegistration) error {
	return h.SubmitValidatorRegistrationsFunc(ctx, registrations)
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

// testBeaconAddr implements eth2client.Service only returning an address.
type testBeaconAddr string

func (t testBeaconAddr) Name() string {
	return string(t)
}

func (t testBeaconAddr) Address() string {
	return string(t)
}
