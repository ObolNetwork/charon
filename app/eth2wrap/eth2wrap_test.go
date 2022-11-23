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

package eth2wrap_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestMulti(t *testing.T) {
	closedErr := errors.New("closed2")

	tests := []struct {
		name   string
		handle func(cl1Resp, cl2Resp chan uint64, ctxCancel context.CancelFunc)
		expErr error
		expRes uint64
	}{
		{
			name: "cl1 only",
			handle: func(cl1Resp, _ chan uint64, _ context.CancelFunc) {
				cl1Resp <- 99
			},
			expRes: 99,
		},
		{
			name: "cl2 only",
			handle: func(_, cl2Resp chan uint64, _ context.CancelFunc) {
				cl2Resp <- 99
			},
			expRes: 99,
		},
		{
			name: "ctx cancel",
			handle: func(_, _ chan uint64, ctxCancel context.CancelFunc) {
				ctxCancel()
			},
			expErr: context.Canceled,
		},
		{
			name: "cl1 error, cl2 ok",
			handle: func(cl1, cl2 chan uint64, _ context.CancelFunc) {
				close(cl1)
				cl2 <- 99
			},
			expRes: 99,
		},
		{
			name: "all error",
			handle: func(cl1, cl2 chan uint64, _ context.CancelFunc) {
				close(cl1)
				close(cl2)
			},
			expErr: closedErr,
		},
		{
			name: "cl1 error, ctx cancel",
			handle: func(cl1, _ chan uint64, cancel context.CancelFunc) {
				close(cl1)
				cancel()
			},
			expErr: context.Canceled,
		},
		{
			name: "cl2 before cl1",
			handle: func(cl1, cl2 chan uint64, cancel context.CancelFunc) {
				cl2 <- 99

				time.Sleep(time.Millisecond)
				cl1 <- 98 // This might flap?
			},
			expRes: 99,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			cl1, err := beaconmock.New()
			require.NoError(t, err)
			cl2, err := beaconmock.New()
			require.NoError(t, err)

			cl1Resp := make(chan uint64)
			cl2Resp := make(chan uint64)

			cl1.SlotsPerEpochFunc = func(ctx context.Context) (uint64, error) {
				select {
				case <-ctx.Done():
					return 0, ctx.Err()
				case resp, ok := <-cl1Resp:
					if !ok {
						return 0, closedErr
					}

					return resp, nil
				}
			}
			cl2.SlotsPerEpochFunc = func(ctx context.Context) (uint64, error) {
				select {
				case <-ctx.Done():
					return 0, ctx.Err()
				case resp, ok := <-cl2Resp:
					if !ok {
						return 0, closedErr
					}

					return resp, nil
				}
			}

			eth2Cl, err := eth2wrap.Instrument(cl1, cl2)
			require.NoError(t, err)

			go test.handle(cl1Resp, cl2Resp, cancel)

			resp, err := eth2Cl.SlotsPerEpoch(ctx)
			require.ErrorIs(t, err, test.expErr)
			require.Equal(t, test.expRes, resp)
		})
	}
}

func TestSyncState(t *testing.T) {
	cl1, err := beaconmock.New()
	require.NoError(t, err)
	cl2, err := beaconmock.New()
	require.NoError(t, err)

	cl1.NodeSyncingFunc = func(ctx context.Context) (*eth2v1.SyncState, error) {
		return &eth2v1.SyncState{IsSyncing: false}, nil
	}
	cl2.NodeSyncingFunc = func(ctx context.Context) (*eth2v1.SyncState, error) {
		return &eth2v1.SyncState{IsSyncing: true}, nil
	}

	eth2Cl, err := eth2wrap.Instrument(cl1, cl2)
	require.NoError(t, err)

	resp, err := eth2Cl.NodeSyncing(context.Background())
	require.NoError(t, err)
	require.False(t, resp.IsSyncing)
}

func TestErrors(t *testing.T) {
	ctx := context.Background()
	t.Run("network dial error", func(t *testing.T) {
		_, err := eth2wrap.NewMultiHTTP(ctx, time.Hour, "localhost:22222")
		log.Error(ctx, "See this error log for fields", err)
		require.Error(t, err)
		require.ErrorContains(t, err, "beacon api new eth2 client: network operation error: dial: connect: connection refused")
	})

	// Test http server that just hangs until request cancelled
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))

	t.Run("http timeout", func(t *testing.T) {
		_, err := eth2wrap.NewMultiHTTP(ctx, time.Millisecond, srv.URL)
		log.Error(ctx, "See this error log for fields", err)
		require.Error(t, err)
		require.ErrorContains(t, err, "beacon api new eth2 client: http request timeout: context deadline exceeded")
	})

	t.Run("caller cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(ctx)
		cancel()
		_, err := eth2wrap.NewMultiHTTP(ctx, time.Millisecond, srv.URL)
		log.Error(ctx, "See this error log for fields", err)
		require.Error(t, err)
		require.ErrorContains(t, err, "beacon api new eth2 client: caller cancelled http request: context canceled")
	})

	t.Run("go-eth2-client http error", func(t *testing.T) {
		bmock, err := beaconmock.New()
		require.NoError(t, err)
		eth2Cl, err := eth2wrap.NewMultiHTTP(ctx, time.Second, bmock.Address())
		require.NoError(t, err)

		_, err = eth2Cl.AggregateAttestation(ctx, 0, eth2p0.Root{})
		log.Error(ctx, "See this error log for fields", err)
		require.Error(t, err)
		require.ErrorContains(t, err, "beacon api aggregate_attestation: nok http response")
	})

	t.Run("zero net op error", func(t *testing.T) {
		bmock, err := beaconmock.New()
		require.NoError(t, err)
		bmock.GenesisTimeFunc = func(context.Context) (time.Time, error) {
			return time.Time{}, new(net.OpError)
		}
		eth2Cl, err := eth2wrap.Instrument(bmock)
		require.NoError(t, err)

		_, err = eth2Cl.GenesisTime(ctx)
		log.Error(ctx, "See this error log for fields", err)
		require.Error(t, err)
		require.ErrorContains(t, err, "beacon api genesis_time: network operation error: :")
	})
}

func TestCtxCancel(t *testing.T) {
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithCancel(context.Background())

		bmock, err := beaconmock.New()
		require.NoError(t, err)
		eth2Cl, err := eth2wrap.NewMultiHTTP(ctx, time.Second, bmock.Address())
		require.NoError(t, err)

		cancel() // Cancel context before calling method.

		_, err = eth2Cl.SlotDuration(ctx)
		require.ErrorIs(t, err, context.Canceled)
	}
}

func TestBlockAttestations(t *testing.T) {
	atts := []*eth2p0.Attestation{
		testutil.RandomAttestation(),
		testutil.RandomAttestation(),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/eth/v1/beacon/blocks/head/attestations", r.URL.Path)
		b, err := json.Marshal(struct {
			Data []*eth2p0.Attestation
		}{
			Data: atts,
		})
		require.NoError(t, err)
		_, _ = w.Write(b)
	}))

	cl := eth2wrap.NewHTTPAdapterForT(t, srv.URL, time.Hour)
	resp, err := cl.BlockAttestations(context.Background(), "head")
	require.NoError(t, err)
	require.Equal(t, atts, resp)
}
