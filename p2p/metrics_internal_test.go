// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/prometheus/client_golang/prometheus"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	pb "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/testutil"
)

// histSample returns the sample count and sum of the histogram for the given label values.
func histSample(t *testing.T, hist *prometheus.HistogramVec, labels ...string) (uint64, float64) {
	t.Helper()

	m := new(pb.Metric)

	h, err := hist.GetMetricWithLabelValues(labels...)
	require.NoError(t, err)
	require.NoError(t, h.(prometheus.Histogram).Write(m))

	return m.GetHistogram().GetSampleCount(), m.GetHistogram().GetSampleSum()
}

func TestMessageSizeMetrics(t *testing.T) {
	var (
		pID    = protocol.ID("test-msg-size")
		ctx    = context.Background()
		client = testutil.CreateHost(t, testutil.AvailableAddr(t))
		server = testutil.CreateHost(t, testutil.AvailableAddr(t))
	)

	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

	RegisterHandler("server", server, pID,
		func() proto.Message { return new(pbv1.Duty) },
		func(_ context.Context, _ peer.ID, req proto.Message) (proto.Message, bool, error) {
			return req, true, nil
		},
	)

	req := &pbv1.Duty{Slot: 123, Type: 4}
	msgSize := float64(proto.Size(req))
	require.Positive(t, msgSize)

	sentCount0, sentSum0 := histSample(t, sentMsgSizeHist, string(pID))
	recvClient0, _ := histSample(t, receivedMsgSizeHist, string(pID), PeerName(server.ID()))
	recvServer0, _ := histSample(t, receivedMsgSizeHist, string(pID), PeerName(client.ID()))

	resp := new(pbv1.Duty)
	require.NoError(t, SendReceive(ctx, client, server.ID(), req, resp, pID))

	// Client sent the request and server sent the identical echoed response.
	sentCount, sentSum := histSample(t, sentMsgSizeHist, string(pID))
	require.Equal(t, sentCount0+2, sentCount)
	require.InDelta(t, sentSum0+2*msgSize, sentSum, 0.1)

	// Server received the request from the client.
	recvServer, recvServerSum := histSample(t, receivedMsgSizeHist, string(pID), PeerName(client.ID()))
	require.Equal(t, recvServer0+1, recvServer)
	require.InDelta(t, msgSize, recvServerSum, 0.1)

	// Client received the response from the server.
	recvClient, _ := histSample(t, receivedMsgSizeHist, string(pID), PeerName(server.ID()))
	require.Equal(t, recvClient0+1, recvClient)
}

func TestMessageReadErrorMetric(t *testing.T) {
	var (
		pID    = protocol.ID("test-read-limit")
		ctx    = context.Background()
		client = testutil.CreateHost(t, testutil.AvailableAddr(t))
		server = testutil.CreateHost(t, testutil.AvailableAddr(t))
	)

	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

	RegisterHandler("server", server, pID,
		func() proto.Message { return new(pbv1.ParSigExMsg) },
		func(context.Context, peer.ID, proto.Message) (proto.Message, bool, error) {
			require.Fail(t, "handler must not be called for oversized message")
			return nil, false, nil
		},
		WithReadLimit(16),
	)

	errCounter := msgReadErrorCounter.WithLabelValues(string(pID), PeerName(client.ID()))
	errCount0 := promtestutil.ToFloat64(errCounter)

	// Message larger than the 16 byte read limit is rejected server side before the handler.
	// Send is one-way so the local write succeeds regardless.
	msg := &pbv1.ParSigExMsg{Duty: &pbv1.Duty{Slot: 99, Type: 2}, DataSet: &pbv1.ParSignedDataSet{
		Set: map[string]*pbv1.ParSignedData{"0xdeadbeef": {Data: make([]byte, 1024), Signature: make([]byte, 96)}},
	}}
	require.NoError(t, Send(ctx, client, pID, server.ID(), msg))

	require.Eventually(t, func() bool {
		return promtestutil.ToFloat64(errCounter) >= errCount0+1
	}, time.Second*5, time.Millisecond*10)
}

func TestInflightRequestMetrics(t *testing.T) {
	var (
		pID    = protocol.ID("test-inflight")
		ctx    = context.Background()
		client = testutil.CreateHost(t, testutil.AvailableAddr(t))
		server = testutil.CreateHost(t, testutil.AvailableAddr(t))
	)

	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

	RegisterHandler("server", server, pID,
		func() proto.Message { return new(pbv1.Duty) },
		func(_ context.Context, _ peer.ID, req proto.Message) (proto.Message, bool, error) {
			return req, true, nil
		},
	)

	clientName := PeerName(client.ID())

	resp := new(pbv1.Duty)
	require.NoError(t, SendReceive(ctx, client, server.ID(), &pbv1.Duty{Slot: 1}, resp, pID))

	// One arrival observed in the concurrency histogram with count 1.
	concCount, concSum := histSample(t, concurrentRequestsHist, string(pID), clientName)
	require.Equal(t, uint64(1), concCount)
	require.InDelta(t, 1, concSum, 0.1)

	// Handler duration observed once.
	durCount, durSum := histSample(t, handlerDuration, string(pID))
	require.Equal(t, uint64(1), durCount)
	require.Positive(t, durSum)

	// In-flight gauge back to zero after completion.
	gauge, err := inflightGauge.GetMetricWithLabelValues(string(pID), clientName)
	require.NoError(t, err)
	require.Zero(t, promtestutil.ToFloat64(gauge))
}

func TestConcurrentRequestDepths(t *testing.T) {
	var (
		pID    = protocol.ID("test-concurrency")
		ctx    = context.Background()
		client = testutil.CreateHost(t, testutil.AvailableAddr(t))
		server = testutil.CreateHost(t, testutil.AvailableAddr(t))
	)

	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

	release := make(chan struct{})
	RegisterHandler("server", server, pID,
		func() proto.Message { return new(pbv1.Duty) },
		func(_ context.Context, _ peer.ID, req proto.Message) (proto.Message, bool, error) {
			<-release
			return req, true, nil
		},
	)

	clientName := PeerName(client.ID())

	// Issue concurrent requests against a blocked handler.
	const n = 3

	var wg sync.WaitGroup
	for range n {
		wg.Add(1)

		go func() {
			defer wg.Done()

			resp := new(pbv1.Duty)
			_ = SendReceive(ctx, client, server.ID(), &pbv1.Duty{Slot: 1}, resp, pID)
		}()
	}

	gauge, err := inflightGauge.GetMetricWithLabelValues(string(pID), clientName)
	require.NoError(t, err)

	// All requests block in the handler, so the gauge reaches n.
	require.Eventually(t, func() bool {
		return promtestutil.ToFloat64(gauge) == n
	}, time.Second*5, time.Millisecond*10)

	close(release)
	wg.Wait()

	// Gauge returns to zero once all handlers complete.
	require.Eventually(t, func() bool {
		return promtestutil.ToFloat64(gauge) == 0
	}, time.Second*5, time.Millisecond*10)

	// The concurrency histogram observed depths 1, 2 and 3 (in some order), so the sum is 6.
	concCount, concSum := histSample(t, concurrentRequestsHist, string(pID), clientName)
	require.Equal(t, uint64(n), concCount)
	require.InDelta(t, 6, concSum, 0.1)
}
