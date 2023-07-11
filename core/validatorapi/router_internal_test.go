// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatorapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2mock "github.com/attestantio/go-eth2-client/mock"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
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

	r, err := NewRouter(Handler(nil), testBeaconAddr{addr: beaconURL})
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

	t.Run("missing query params", func(t *testing.T) {
		handler := testHandler{}

		callback := func(ctx context.Context, baseURL string) {
			res, err := http.Post(baseURL+"/eth/v2/validator/blocks/123", "", nil)
			require.NoError(t, err)

			var errRes errorResponse
			err = json.NewDecoder(res.Body).Decode(&errRes)
			require.NoError(t, err)
			require.Equal(t, errRes, errorResponse{
				Code:    http.StatusBadRequest,
				Message: "missing 0x-hex query parameter randao_reveal",
			})
		}

		testRawRouter(t, handler, callback)
	})

	t.Run("invalid length query params", func(t *testing.T) {
		handler := testHandler{}

		callback := func(ctx context.Context, baseURL string) {
			res, err := http.Post(baseURL+"/eth/v2/validator/blocks/123?randao_reveal=0x0000", "", nil)
			require.NoError(t, err)

			var errRes errorResponse
			err = json.NewDecoder(res.Body).Decode(&errRes)
			require.NoError(t, err)
			require.Equal(t, errRes, errorResponse{
				Code:    http.StatusBadRequest,
				Message: "invalid length for 0x-hex query parameter randao_reveal, expect 96 bytes",
			})
		}

		testRawRouter(t, handler, callback)
	})

	t.Run("empty graffiti", func(t *testing.T) {
		handler := testHandler{}
		handler.BeaconBlockProposalFunc = func(ctx context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature, graffiti []byte) (*eth2spec.VersionedBeaconBlock, error) {
			require.Empty(t, graffiti)
			resp := testutil.RandomBellatrixCoreVersionedBeaconBlock().VersionedBeaconBlock

			return &resp, nil
		}

		callback := func(ctx context.Context, baseURL string) {
			randao := testutil.RandomEth2Signature().String()
			res, err := http.Post(baseURL+"/eth/v2/validator/blocks/123?randao_reveal="+randao, "", nil)
			require.NoError(t, err)

			var okResp struct{ Data json.RawMessage }
			err = json.NewDecoder(res.Body).Decode(&okResp)
			require.NoError(t, err)
			require.NotEmpty(t, okResp.Data)
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
				Message: "failed parsing json request body",
			})
		}

		testRawRouter(t, handler, callback)
	})

	t.Run("valid content type in 2xx response", func(t *testing.T) {
		handler := testHandler{}

		callback := func(ctx context.Context, baseURL string) {
			res, err := http.Get(baseURL + "/eth/v1/node/version")
			require.NoError(t, err)
			require.Equal(t, res.Header.Get("Content-Type"), "application/json")
		}

		testRawRouter(t, handler, callback)
	})

	t.Run("valid content type in non-2xx response", func(t *testing.T) {
		handler := testHandler{}

		callback := func(ctx context.Context, baseURL string) {
			res, err := http.Post(baseURL+"/eth/v1/validator/duties/attester/1", "", strings.NewReader("not json"))
			require.NoError(t, err)
			require.Equal(t, res.Header.Get("Content-Type"), "application/json")
			var errRes errorResponse
			require.NoError(t, json.NewDecoder(res.Body).Decode(&errRes))
			require.Equal(t, errRes.Code, http.StatusBadRequest)
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
			req, err := http.NewRequestWithContext(cctx, http.MethodGet, baseURL+"/eth/v1/beacon/states/head/validators/12", nil)
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

	t.Run("submit bellatrix ssz beacon block", func(t *testing.T) {
		var done atomic.Bool
		coreBlock := testutil.RandomBellatrixCoreVersionedSignedBeaconBlock()
		block := &coreBlock.VersionedSignedBeaconBlock

		handler := testHandler{
			SubmitBeaconBlockFunc: func(ctx context.Context, actual *eth2spec.VersionedSignedBeaconBlock) error {
				require.Equal(t, block, actual)
				done.Store(true)

				return nil
			},
		}

		callback := func(ctx context.Context, baseURL string) {
			b, err := ssz.MarshalSSZ(block.Bellatrix)
			require.NoError(t, err)

			req, err := http.NewRequestWithContext(ctx, http.MethodPost,
				baseURL+"/eth/v1/beacon/blocks", bytes.NewReader(b))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/octet-stream")

			resp, err := new(http.Client).Do(req)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		}

		testRawRouter(t, handler, callback)
		require.True(t, done.Load())
	})

	t.Run("submit capella ssz beacon block", func(t *testing.T) {
		var done atomic.Bool
		block := testutil.RandomCapellaVersionedSignedBeaconBlock()

		handler := testHandler{
			SubmitBeaconBlockFunc: func(ctx context.Context, actual *eth2spec.VersionedSignedBeaconBlock) error {
				require.Equal(t, block, actual)
				done.Store(true)

				return nil
			},
		}

		callback := func(ctx context.Context, baseURL string) {
			b, err := ssz.MarshalSSZ(block.Capella)
			require.NoError(t, err)

			req, err := http.NewRequestWithContext(ctx, http.MethodPost,
				baseURL+"/eth/v1/beacon/blocks", bytes.NewReader(b))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/octet-stream")

			resp, err := new(http.Client).Do(req)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		}

		testRawRouter(t, handler, callback)
		require.True(t, done.Load())
	})

	t.Run("get response header for beacon block proposal", func(t *testing.T) {
		block := &eth2spec.VersionedBeaconBlock{
			Version: eth2spec.DataVersionCapella,
			Capella: testutil.RandomCapellaBeaconBlock(),
		}
		expectedSlot, err := block.Slot()
		require.NoError(t, err)
		randao := block.Capella.Body.RANDAOReveal
		handler := testHandler{
			BeaconBlockProposalFunc: func(ctx context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature, graffiti []byte) (*eth2spec.VersionedBeaconBlock, error) {
				require.Equal(t, expectedSlot, slot)
				require.Equal(t, randao, randaoReveal)

				return block, nil
			},
		}

		callback := func(ctx context.Context, baseURL string) {
			res, err := http.Get(baseURL + fmt.Sprintf("/eth/v2/validator/blocks/%d?randao_reveal=%#x", expectedSlot, randao))
			require.NoError(t, err)

			// Verify response header.
			require.Equal(t, block.Version.String(), res.Header.Get("Eth-Consensus-Version"))

			var blockRes proposeBlockResponseCapella
			err = json.NewDecoder(res.Body).Decode(&blockRes)
			require.NoError(t, err)
			require.EqualValues(t, block.Capella, blockRes.Data)
		}

		testRawRouter(t, handler, callback)
	})

	t.Run("get response header for blinded block proposal", func(t *testing.T) {
		block := &eth2api.VersionedBlindedBeaconBlock{
			Version: eth2spec.DataVersionCapella,
			Capella: testutil.RandomCapellaBlindedBeaconBlock(),
		}
		expectedSlot, err := block.Slot()
		require.NoError(t, err)
		randao := block.Capella.Body.RANDAOReveal
		handler := testHandler{
			BlindedBeaconBlockProposalFunc: func(ctx context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature, graffiti []byte) (*eth2api.VersionedBlindedBeaconBlock, error) {
				require.Equal(t, expectedSlot, slot)
				require.Equal(t, randao, randaoReveal)

				return block, nil
			},
		}

		callback := func(ctx context.Context, baseURL string) {
			res, err := http.Get(baseURL + fmt.Sprintf("/eth/v1/validator/blinded_blocks/%d?randao_reveal=%#x", expectedSlot, randao))
			require.NoError(t, err)

			// Verify response header.
			require.Equal(t, block.Version.String(), res.Header.Get("Eth-Consensus-Version"))

			var blockRes proposeBlindedBlockResponseCapella
			err = json.NewDecoder(res.Body).Decode(&blockRes)
			require.NoError(t, err)
			require.EqualValues(t, block.Capella, blockRes.Data)
		}

		testRawRouter(t, handler, callback)
	})
}

//nolint:maintidx // This function is a test of tests, so analysed as "complex".
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

	t.Run("synccommduty", func(t *testing.T) {
		handler := testHandler{
			SyncCommitteeDutiesFunc: func(ctx context.Context, epoch eth2p0.Epoch, vIdxs []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error) {
				// Returns ordered total number of duties for the epoch
				var res []*eth2v1.SyncCommitteeDuty
				for _, vIdx := range vIdxs {
					res = append(res, &eth2v1.SyncCommitteeDuty{
						ValidatorIndex:                vIdx,
						ValidatorSyncCommitteeIndices: []eth2p0.CommitteeIndex{eth2p0.CommitteeIndex(vIdx)},
					})
				}

				return res, nil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			const epoch = 4
			const validator = 1
			res, err := cl.SyncCommitteeDuties(ctx, eth2p0.Epoch(epoch), []eth2p0.ValidatorIndex{
				eth2p0.ValidatorIndex(validator), // Only request 1 of total 2 validators
			})
			require.NoError(t, err)

			require.Len(t, res, 1)
			require.Equal(t, res[0].ValidatorSyncCommitteeIndices, []eth2p0.CommitteeIndex{eth2p0.CommitteeIndex(validator)})
			require.Equal(t, int(res[0].ValidatorIndex), validator)
		}

		testRouter(t, handler, callback)
	})

	t.Run("get validator index", func(t *testing.T) {
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

	t.Run("get validator pubkeu", func(t *testing.T) {
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

	t.Run("empty validators", func(t *testing.T) {
		handler := testHandler{
			ValidatorsByPubKeyFunc: func(context.Context, string, []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
				return nil, nil //nolint:nilnil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			res, err := cl.ValidatorsByPubKey(ctx, "head", []eth2p0.BLSPubKey{
				testutil.RandomEth2PubKey(t),
				testutil.RandomEth2PubKey(t),
			})
			require.NoError(t, err)
			require.Len(t, res, 0)
		}

		testRouter(t, handler, callback)
	})

	t.Run("get validators with no validator ids provided", func(t *testing.T) {
		const numVals = 2
		handler := testHandler{}
		callback := func(ctx context.Context, cl *eth2http.Service) {
			// Validators fetches all validators from beacon state as per go-eth2-client v0.18.0.
			res, err := cl.Validators(ctx, "head", nil)
			require.NoError(t, err)
			require.Len(t, res, numVals)
		}

		testRouter(t, handler, callback)
	})

	t.Run("empty attester duties", func(t *testing.T) {
		handler := testHandler{
			AttesterDutiesFunc: func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
				return nil, nil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			res, err := cl.AttesterDuties(ctx, eth2p0.Epoch(1), []eth2p0.ValidatorIndex{1, 2, 3})
			require.NoError(t, err)
			require.Len(t, res, 0)
		}

		testRouter(t, handler, callback)
	})

	t.Run("empty synccomm duties", func(t *testing.T) {
		handler := testHandler{
			SyncCommitteeDutiesFunc: func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error) {
				return nil, nil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			res, err := cl.SyncCommitteeDuties(ctx, eth2p0.Epoch(1), []eth2p0.ValidatorIndex{1, 2, 3})
			require.NoError(t, err)
			require.Len(t, res, 0)
		}

		testRouter(t, handler, callback)
	})

	t.Run("empty proposer duties", func(t *testing.T) {
		handler := testHandler{
			ProposerDutiesFunc: func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
				return nil, nil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			res, err := cl.ProposerDuties(ctx, eth2p0.Epoch(1), []eth2p0.ValidatorIndex{1, 2, 3})
			require.NoError(t, err)
			require.Len(t, res, 0)
		}

		testRouter(t, handler, callback)
	})

	t.Run("attestation data", func(t *testing.T) {
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

	t.Run("submit randao", func(t *testing.T) {
		handler := testHandler{
			BeaconBlockProposalFunc: func(ctx context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature, graffiti []byte) (*eth2spec.VersionedBeaconBlock, error) {
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

	t.Run("submit randao blinded block", func(t *testing.T) {
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

	t.Run("submit block phase0", func(t *testing.T) {
		block1 := &eth2spec.VersionedSignedBeaconBlock{
			Version: eth2spec.DataVersionPhase0,
			Phase0: &eth2p0.SignedBeaconBlock{
				Message:   testutil.RandomPhase0BeaconBlock(),
				Signature: testutil.RandomEth2Signature(),
			},
		}
		handler := testHandler{
			SubmitBeaconBlockFunc: func(ctx context.Context, block *eth2spec.VersionedSignedBeaconBlock) error {
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

	t.Run("submit block altair", func(t *testing.T) {
		block1 := &eth2spec.VersionedSignedBeaconBlock{
			Version: eth2spec.DataVersionAltair,
			Altair: &altair.SignedBeaconBlock{
				Message:   testutil.RandomAltairBeaconBlock(),
				Signature: testutil.RandomEth2Signature(),
			},
		}
		handler := testHandler{
			SubmitBeaconBlockFunc: func(ctx context.Context, block *eth2spec.VersionedSignedBeaconBlock) error {
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

	t.Run("submit block bellatrix", func(t *testing.T) {
		block1 := &eth2spec.VersionedSignedBeaconBlock{
			Version: eth2spec.DataVersionBellatrix,
			Bellatrix: &bellatrix.SignedBeaconBlock{
				Message:   testutil.RandomBellatrixBeaconBlock(),
				Signature: testutil.RandomEth2Signature(),
			},
		}
		handler := testHandler{
			SubmitBeaconBlockFunc: func(ctx context.Context, block *eth2spec.VersionedSignedBeaconBlock) error {
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

	t.Run("submit block capella", func(t *testing.T) {
		block1 := &eth2spec.VersionedSignedBeaconBlock{
			Version: eth2spec.DataVersionCapella,
			Capella: &capella.SignedBeaconBlock{
				Message:   testutil.RandomCapellaBeaconBlock(),
				Signature: testutil.RandomEth2Signature(),
			},
		}
		handler := testHandler{
			SubmitBeaconBlockFunc: func(ctx context.Context, block *eth2spec.VersionedSignedBeaconBlock) error {
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

	t.Run("submit blinded block bellatrix", func(t *testing.T) {
		block1 := &eth2api.VersionedSignedBlindedBeaconBlock{
			Version: eth2spec.DataVersionBellatrix,
			Bellatrix: &eth2bellatrix.SignedBlindedBeaconBlock{
				Message:   testutil.RandomBellatrixBlindedBeaconBlock(),
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

	t.Run("submit blinded block capella", func(t *testing.T) {
		block1 := &eth2api.VersionedSignedBlindedBeaconBlock{
			Version: eth2spec.DataVersionCapella,
			Capella: &eth2capella.SignedBlindedBeaconBlock{
				Message:   testutil.RandomCapellaBlindedBeaconBlock(),
				Signature: testutil.RandomEth2Signature(),
			},
		}
		handler := testHandler{
			SubmitBlindedBeaconBlockFunc: func(ctx context.Context, block *eth2api.VersionedSignedBlindedBeaconBlock) error {
				require.Equal(t, block1, block)
				return nil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			err := cl.SubmitBlindedBeaconBlock(ctx, block1)
			require.NoError(t, err)
		}

		testRouter(t, handler, callback)
	})

	t.Run("submit validator registration", func(t *testing.T) {
		expect := []*eth2api.VersionedSignedValidatorRegistration{
			{
				Version: eth2spec.BuilderVersionV1,
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

	t.Run("submit voluntary exit", func(t *testing.T) {
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

	t.Run("sync committee contribution", func(t *testing.T) {
		handler := testHandler{
			SyncCommitteeContributionFunc: func(ctx context.Context, slot eth2p0.Slot, subcommitteeIndex uint64, beaconBlockRoot eth2p0.Root) (*altair.SyncCommitteeContribution, error) {
				contrib := testutil.RandomSyncCommitteeContribution()
				contrib.Slot = slot
				contrib.SubcommitteeIndex = subcommitteeIndex
				contrib.BeaconBlockRoot = beaconBlockRoot

				return contrib, nil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			var (
				slot            = testutil.RandomSlot()
				subcommIdx      = testutil.RandomCommIdx()
				beaconBlockRoot = testutil.RandomRoot()
			)

			resp, err := cl.SyncCommitteeContribution(ctx, slot, uint64(subcommIdx), beaconBlockRoot)
			require.NoError(t, err)

			require.Equal(t, resp.Slot, slot)
			require.EqualValues(t, resp.SubcommitteeIndex, subcommIdx)
			require.EqualValues(t, resp.BeaconBlockRoot, beaconBlockRoot)
		}

		testRouter(t, handler, callback)
	})

	t.Run("submit sync committee messages", func(t *testing.T) {
		msgs := []*altair.SyncCommitteeMessage{testutil.RandomSyncCommitteeMessage(), testutil.RandomSyncCommitteeMessage()}

		handler := testHandler{
			SubmitSyncCommitteeMessagesFunc: func(ctx context.Context, messages []*altair.SyncCommitteeMessage) error {
				for i := range msgs {
					require.Equal(t, msgs[i], messages[i])
				}

				return nil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			require.NoError(t, cl.SubmitSyncCommitteeMessages(ctx, msgs))
		}

		testRouter(t, handler, callback)
	})

	t.Run("aggregate sync committee selections", func(t *testing.T) {
		selections := []*eth2exp.SyncCommitteeSelection{testutil.RandomSyncCommitteeSelection(), testutil.RandomSyncCommitteeSelection()}

		handler := testHandler{
			AggregateSyncCommitteeSelectionsFunc: func(ctx context.Context, partialSelections []*eth2exp.SyncCommitteeSelection) ([]*eth2exp.SyncCommitteeSelection, error) {
				for i := range selections {
					require.Equal(t, selections[i], partialSelections[i])
				}

				return partialSelections, nil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			eth2Cl := eth2wrap.AdaptEth2HTTP(cl, time.Second)
			actual, err := eth2Cl.AggregateSyncCommitteeSelections(ctx, selections)
			require.NoError(t, err)
			require.Equal(t, selections, actual)
		}

		testRouter(t, handler, callback)
	})

	t.Run("node version", func(t *testing.T) {
		expectedVersion := "obolnetwork/charon/v0.25.0-eth123b/darwin-arm64"

		handler := testHandler{
			NodeVersionFunc: func(ctx context.Context) (string, error) {
				return expectedVersion, nil
			},
		}

		callback := func(ctx context.Context, cl *eth2http.Service) {
			actualVersion, err := cl.NodeVersion(ctx)
			require.NoError(t, err)
			require.Equal(t, expectedVersion, actualVersion)
		}

		testRouter(t, handler, callback)
	})
}

func TestBeaconCommitteeSelections(t *testing.T) {
	ctx := context.Background()

	const (
		slotA = 123
		slotB = 456
		vIdxA = 1
		vIdxB = 2
		vIdxC = 3
	)

	handler := testHandler{
		AggregateBeaconCommitteeSelectionsFunc: func(ctx context.Context, selections []*eth2exp.BeaconCommitteeSelection) ([]*eth2exp.BeaconCommitteeSelection, error) {
			return selections, nil
		},
	}

	proxy := httptest.NewServer(handler.newBeaconHandler(t))
	defer proxy.Close()

	r, err := NewRouter(handler, testBeaconAddr{addr: proxy.URL})
	require.NoError(t, err)

	server := httptest.NewServer(r)
	defer server.Close()

	var eth2Svc eth2client.Service
	eth2Svc, err = eth2http.New(ctx,
		eth2http.WithLogLevel(1),
		eth2http.WithAddress(server.URL),
	)
	require.NoError(t, err)

	selections := []*eth2exp.BeaconCommitteeSelection{
		{
			Slot:           slotA,
			ValidatorIndex: vIdxA,
			SelectionProof: testutil.RandomEth2Signature(),
		},
		{
			Slot:           slotB,
			ValidatorIndex: vIdxB,
			SelectionProof: testutil.RandomEth2Signature(),
		},
		{
			Slot:           slotA,
			ValidatorIndex: vIdxC,
			SelectionProof: testutil.RandomEth2Signature(),
		},
	}

	eth2Cl := eth2wrap.AdaptEth2HTTP(eth2Svc.(*eth2http.Service), time.Second)
	actual, err := eth2Cl.AggregateBeaconCommitteeSelections(ctx, selections)
	require.NoError(t, err)
	require.Equal(t, selections, actual)
}

func TestSubmitAggregateAttestations(t *testing.T) {
	ctx := context.Background()

	const vIdx = 1

	agg := &eth2p0.SignedAggregateAndProof{
		Message: &eth2p0.AggregateAndProof{
			AggregatorIndex: vIdx,
			Aggregate:       testutil.RandomAttestation(),
			SelectionProof:  testutil.RandomEth2Signature(),
		},
		Signature: testutil.RandomEth2Signature(),
	}

	handler := testHandler{
		SubmitAggregateAttestationsFunc: func(_ context.Context, aggregateAndProofs []*eth2p0.SignedAggregateAndProof) error {
			require.Equal(t, agg, aggregateAndProofs[0])

			return nil
		},
	}

	proxy := httptest.NewServer(handler.newBeaconHandler(t))
	defer proxy.Close()

	r, err := NewRouter(handler, testBeaconAddr{addr: proxy.URL})
	require.NoError(t, err)

	server := httptest.NewServer(r)
	defer server.Close()

	var eth2Svc eth2client.Service
	eth2Svc, err = eth2http.New(ctx,
		eth2http.WithLogLevel(1),
		eth2http.WithAddress(server.URL),
	)
	require.NoError(t, err)

	eth2Cl := eth2wrap.AdaptEth2HTTP(eth2Svc.(*eth2http.Service), time.Second)
	err = eth2Cl.SubmitAggregateAttestations(ctx, []*eth2p0.SignedAggregateAndProof{agg})
	require.NoError(t, err)
}

// testRouter is a helper function to test router endpoints with an eth2http client. The outer test
// provides the mocked test handler and a callback that does the client side test.
func testRouter(t *testing.T, handler testHandler, callback func(context.Context, *eth2http.Service)) {
	t.Helper()
	proxy := httptest.NewServer(handler.newBeaconHandler(t))
	defer proxy.Close()

	r, err := NewRouter(handler, testBeaconAddr{addr: proxy.URL})
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

	r, err := NewRouter(handler, testBeaconAddr{addr: proxy.URL})
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
	ProxyHandler                           http.HandlerFunc
	AggregateSyncCommitteeSelectionsFunc   func(ctx context.Context, partialSelections []*eth2exp.SyncCommitteeSelection) ([]*eth2exp.SyncCommitteeSelection, error)
	AttestationDataFunc                    func(ctx context.Context, slot eth2p0.Slot, commIdx eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error)
	AttesterDutiesFunc                     func(ctx context.Context, epoch eth2p0.Epoch, il []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error)
	BeaconBlockProposalFunc                func(ctx context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature, graffiti []byte) (*eth2spec.VersionedBeaconBlock, error)
	SubmitBeaconBlockFunc                  func(ctx context.Context, block *eth2spec.VersionedSignedBeaconBlock) error
	BlindedBeaconBlockProposalFunc         func(ctx context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature, graffiti []byte) (*eth2api.VersionedBlindedBeaconBlock, error)
	SubmitBlindedBeaconBlockFunc           func(ctx context.Context, block *eth2api.VersionedSignedBlindedBeaconBlock) error
	ProposerDutiesFunc                     func(ctx context.Context, epoch eth2p0.Epoch, il []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error)
	NodeVersionFunc                        func(ctx context.Context) (string, error)
	ValidatorsFunc                         func(ctx context.Context, stateID string, indices []eth2p0.ValidatorIndex) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error)
	ValidatorsByPubKeyFunc                 func(ctx context.Context, stateID string, pubkeys []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error)
	SubmitVoluntaryExitFunc                func(ctx context.Context, exit *eth2p0.SignedVoluntaryExit) error
	SubmitValidatorRegistrationsFunc       func(ctx context.Context, registrations []*eth2api.VersionedSignedValidatorRegistration) error
	AggregateBeaconCommitteeSelectionsFunc func(ctx context.Context, selections []*eth2exp.BeaconCommitteeSelection) ([]*eth2exp.BeaconCommitteeSelection, error)
	SubmitAggregateAttestationsFunc        func(ctx context.Context, aggregateAndProofs []*eth2p0.SignedAggregateAndProof) error
	SubmitSyncCommitteeMessagesFunc        func(ctx context.Context, messages []*altair.SyncCommitteeMessage) error
	SyncCommitteeDutiesFunc                func(ctx context.Context, epoch eth2p0.Epoch, validatorIndices []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error)
	SyncCommitteeContributionFunc          func(ctx context.Context, slot eth2p0.Slot, subcommitteeIndex uint64, beaconBlockRoot eth2p0.Root) (*altair.SyncCommitteeContribution, error)
}

func (h testHandler) AttestationData(ctx context.Context, slot eth2p0.Slot, commIdx eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error) {
	return h.AttestationDataFunc(ctx, slot, commIdx)
}

func (h testHandler) AttesterDuties(ctx context.Context, epoch eth2p0.Epoch, il []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
	return h.AttesterDutiesFunc(ctx, epoch, il)
}

func (h testHandler) BeaconBlockProposal(ctx context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature, graffiti []byte) (*eth2spec.VersionedBeaconBlock, error) {
	return h.BeaconBlockProposalFunc(ctx, slot, randaoReveal, graffiti)
}

func (h testHandler) SubmitBeaconBlock(ctx context.Context, block *eth2spec.VersionedSignedBeaconBlock) error {
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

func (h testHandler) NodeVersion(ctx context.Context) (string, error) {
	if h.NodeVersionFunc != nil {
		return h.NodeVersionFunc(ctx)
	}

	return "mock_version", nil
}

func (h testHandler) SubmitVoluntaryExit(ctx context.Context, exit *eth2p0.SignedVoluntaryExit) error {
	return h.SubmitVoluntaryExitFunc(ctx, exit)
}

func (h testHandler) SubmitValidatorRegistrations(ctx context.Context, registrations []*eth2api.VersionedSignedValidatorRegistration) error {
	return h.SubmitValidatorRegistrationsFunc(ctx, registrations)
}

func (h testHandler) AggregateBeaconCommitteeSelections(ctx context.Context, selections []*eth2exp.BeaconCommitteeSelection) ([]*eth2exp.BeaconCommitteeSelection, error) {
	return h.AggregateBeaconCommitteeSelectionsFunc(ctx, selections)
}

func (h testHandler) SubmitAggregateAttestations(ctx context.Context, aggregateAndProofs []*eth2p0.SignedAggregateAndProof) error {
	return h.SubmitAggregateAttestationsFunc(ctx, aggregateAndProofs)
}

func (h testHandler) SubmitSyncCommitteeMessages(ctx context.Context, messages []*altair.SyncCommitteeMessage) error {
	return h.SubmitSyncCommitteeMessagesFunc(ctx, messages)
}

func (h testHandler) SyncCommitteeDuties(ctx context.Context, epoch eth2p0.Epoch, validatorIndices []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error) {
	return h.SyncCommitteeDutiesFunc(ctx, epoch, validatorIndices)
}

func (h testHandler) SyncCommitteeContribution(ctx context.Context, slot eth2p0.Slot, subcommitteeIndex uint64, beaconBlockRoot eth2p0.Root) (*altair.SyncCommitteeContribution, error) {
	return h.SyncCommitteeContributionFunc(ctx, slot, subcommitteeIndex, beaconBlockRoot)
}

func (h testHandler) AggregateSyncCommitteeSelections(ctx context.Context, partialSelections []*eth2exp.SyncCommitteeSelection) ([]*eth2exp.SyncCommitteeSelection, error) {
	return h.AggregateSyncCommitteeSelectionsFunc(ctx, partialSelections)
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
		writeResponse(ctx, w, "", res, nil)
	})
	mux.HandleFunc("/eth/v1/config/spec", func(w http.ResponseWriter, r *http.Request) {
		res := map[string]interface{}{
			"SLOTS_PER_EPOCH": fmt.Sprint(slotsPerEpoch),
		}
		writeResponse(ctx, w, "", nest(res, "data"), nil)
	})
	mux.HandleFunc("/eth/v1/config/deposit_contract", func(w http.ResponseWriter, r *http.Request) {
		res, err := mock.DepositContract(ctx)
		require.NoError(t, err)
		writeResponse(ctx, w, "", res, nil)
	})
	mux.HandleFunc("/eth/v1/config/fork_schedule", func(w http.ResponseWriter, r *http.Request) {
		res, err := mock.ForkSchedule(ctx)
		require.NoError(t, err)
		writeResponse(ctx, w, "", nest(res, "data"), nil)
	})
	mux.HandleFunc("/eth/v2/debug/beacon/states/head", func(w http.ResponseWriter, r *http.Request) {
		res := testutil.RandomBeaconState(t)
		w.Header().Add("Eth-Consensus-Version", res.Version.String())

		writeResponse(ctx, w, "", nest(res.Capella, "data"))
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
type testBeaconAddr struct {
	eth2wrap.Client
	addr string
}

func (t testBeaconAddr) Address() string {
	return t.addr
}
