package validatorapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2mock "github.com/attestantio/go-eth2-client/mock"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestRouterAttesterDuties(t *testing.T) {
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
		const slotEpoch = 10
		const index0 = 20
		const index1 = 20
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
}

func (h testHandler) AttesterDuties(ctx context.Context, epoch eth2p0.Epoch, il []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
	return h.AttesterDutiesFunc(ctx, epoch, il)
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
		res, err := mock.Spec(ctx)
		require.NoError(t, err)
		writeResponse(w, res)
	})
	mux.HandleFunc("/eth/v1/config/deposit_contract", func(w http.ResponseWriter, r *http.Request) {
		res, err := mock.DepositContract(ctx)
		require.NoError(t, err)
		writeResponse(w, res)
	})
	mux.HandleFunc("/eth/v1/config/fork_schedule", func(w http.ResponseWriter, r *http.Request) {
		res, err := mock.ForkSchedule(ctx)
		require.NoError(t, err)
		writeResponse(w, wrapDataResponse(res))
	})
	mux.HandleFunc("/eth/v1/node/version", func(w http.ResponseWriter, r *http.Request) {
		res, err := mock.NodeVersion(ctx)
		require.NoError(t, err)
		writeResponse(w, wrapDataResponse(struct {
			Version string
		}{
			Version: res,
		}))
	})

	if h.ProxyHandler != nil {
		mux.HandleFunc("/", h.ProxyHandler)
	}

	return mux
}

// wrapDataResponse some endpoints need to wrap their response as a data field.
func wrapDataResponse(data interface{}) interface{} {
	return struct {
		Data interface{} `json:"data"`
	}{
		Data: data,
	}
}
