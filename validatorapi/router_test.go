package validatorapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2mock "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

const slotsPerEpoch = 32

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
			ProposerDutiesFunc: func(ctx context.Context, epoch phase0.Epoch, _ []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
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
}

// testRouter is a helper function to test router endpoints. The outer test
// provides the mocked test handler and a callback that does the client side test.
func testRouter(t *testing.T, handler testHandler, callback func(context.Context, *eth2http.Service)) {
	proxy := httptest.NewServer(handler.newBeaconHandler(t))
	defer proxy.Close()

	r, err := NewRouter(handler, proxy.URL)
	require.NoError(t, err)

	server := httptest.NewServer(r)
	defer server.Close()

	ctx := context.Background()

	cl, err := eth2http.New(ctx, eth2http.WithAddress(server.URL), eth2http.WithLogLevel(zerolog.InfoLevel))
	require.NoError(t, err)

	callback(ctx, cl.(*eth2http.Service))
}

type testHandler struct {
	Handler
	ProxyHandler       http.HandlerFunc
	AttesterDutiesFunc func(ctx context.Context, epoch eth2p0.Epoch, il []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error)
	ProposerDutiesFunc func(ctx context.Context, epoch phase0.Epoch, il []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error)
}

func (h testHandler) AttesterDuties(ctx context.Context, epoch eth2p0.Epoch, il []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
	return h.AttesterDutiesFunc(ctx, epoch, il)
}

func (h testHandler) ProposerDuties(ctx context.Context, epoch phase0.Epoch, il []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
	return h.ProposerDutiesFunc(ctx, epoch, il)
}

// newBeaconHandler returns a mock beacon node handler. It registers a few mock handlers required by the
// eth2http service on startup, all other requests are routed to ProxyHandler if not nil.
func (h testHandler) newBeaconHandler(t *testing.T) http.Handler {
	ctx := context.Background()
	mock, err := eth2mock.New(ctx, eth2mock.WithLogLevel(zerolog.InfoLevel))
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/eth/v1/beacon/genesis", func(w http.ResponseWriter, r *http.Request) {
		res, err := mock.Genesis(ctx)
		require.NoError(t, err)
		writeResponse(w, res)
	})
	mux.HandleFunc("/eth/v1/config/spec", func(w http.ResponseWriter, r *http.Request) {
		res := map[string]interface{}{
			"SLOTS_PER_EPOCH": fmt.Sprint(slotsPerEpoch),
		}
		writeResponse(w, nest(res, "data"))
	})
	mux.HandleFunc("/eth/v1/config/deposit_contract", func(w http.ResponseWriter, r *http.Request) {
		res, err := mock.DepositContract(ctx)
		require.NoError(t, err)
		writeResponse(w, res)
	})
	mux.HandleFunc("/eth/v1/config/fork_schedule", func(w http.ResponseWriter, r *http.Request) {
		res, err := mock.ForkSchedule(ctx)
		require.NoError(t, err)
		writeResponse(w, nest(res, "data"))
	})
	mux.HandleFunc("/eth/v1/node/version", func(w http.ResponseWriter, r *http.Request) {
		res, err := mock.NodeVersion(ctx)
		require.NoError(t, err)
		writeResponse(w, nest(res, "version", "data"))
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
