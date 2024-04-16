// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package relay

import (
	"time"

	"github.com/libp2p/go-libp2p/p2p/metricshelper"
	pbv2 "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/pb"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/prometheus/client_golang/prometheus"
)

// This implementation must be kept in sync with metricsTracer in
// https://github.com/libp2p/go-libp2p/blob/master/p2p/protocol/circuitv2/relay/metrics.go

const (
	requestStatusOK       = "ok"
	requestStatusRejected = "rejected"
	requestStatusError    = "error"
)

var collectors = []prometheus.Collector{
	intStatus,
	intReservationsTotal,
	intReservationRequestResponseStatusTotal,
	intReservationRejectionsTotal,
	intConnectionsTotal,
	intConnectionRequestResponseStatusTotal,
	intConnectionRejectionsTotal,
	intConnectionDurationSeconds,
	intDataTransferredBytesTotal,
}

func NewMetricsTracer(promRegisterer prometheus.Registerer) relay.MetricsTracer {
	metricshelper.RegisterCollectors(promRegisterer, collectors...)

	return &metricsTracer{}
}

type metricsTracer struct{}

func (*metricsTracer) RelayStatus(enabled bool) {
	if enabled {
		intStatus.Set(1)
	} else {
		intStatus.Set(0)
	}
}

func (*metricsTracer) ConnectionOpened() {
	tags := metricshelper.GetStringSlice()
	defer metricshelper.PutStringSlice(tags)
	*tags = append(*tags, "opened")

	intConnectionsTotal.WithLabelValues(*tags...).Add(1)
}

func (*metricsTracer) ConnectionClosed(d time.Duration) {
	tags := metricshelper.GetStringSlice()
	defer metricshelper.PutStringSlice(tags)
	*tags = append(*tags, "closed")

	intConnectionsTotal.WithLabelValues(*tags...).Add(1)
	intConnectionDurationSeconds.Observe(d.Seconds())
}

func (*metricsTracer) ConnectionRequestHandled(status pbv2.Status) {
	tags := metricshelper.GetStringSlice()
	defer metricshelper.PutStringSlice(tags)

	respStatus := getResponseStatus(status)

	*tags = append(*tags, respStatus)
	intConnectionRequestResponseStatusTotal.WithLabelValues(*tags...).Add(1)
	if respStatus == requestStatusRejected {
		*tags = (*tags)[:0]
		*tags = append(*tags, getRejectionReason(status))
		intConnectionRejectionsTotal.WithLabelValues(*tags...).Add(1)
	}
}

func (*metricsTracer) ReservationAllowed(isRenewal bool) {
	tags := metricshelper.GetStringSlice()
	defer metricshelper.PutStringSlice(tags)
	if isRenewal {
		*tags = append(*tags, "renewed")
	} else {
		*tags = append(*tags, "opened")
	}

	intReservationsTotal.WithLabelValues(*tags...).Add(1)
}

func (*metricsTracer) ReservationClosed(cnt int) {
	tags := metricshelper.GetStringSlice()
	defer metricshelper.PutStringSlice(tags)
	*tags = append(*tags, "closed")

	intReservationsTotal.WithLabelValues(*tags...).Add(float64(cnt))
}

func (*metricsTracer) ReservationRequestHandled(status pbv2.Status) {
	tags := metricshelper.GetStringSlice()
	defer metricshelper.PutStringSlice(tags)

	respStatus := getResponseStatus(status)

	*tags = append(*tags, respStatus)
	intReservationRequestResponseStatusTotal.WithLabelValues(*tags...).Add(1)
	if respStatus == requestStatusRejected {
		*tags = (*tags)[:0]
		*tags = append(*tags, getRejectionReason(status))
		intReservationRejectionsTotal.WithLabelValues(*tags...).Add(1)
	}
}

func (*metricsTracer) BytesTransferred(cnt int) {
	intDataTransferredBytesTotal.Add(float64(cnt))
}

func getResponseStatus(status pbv2.Status) string {
	responseStatus := "unknown"
	switch status {
	case pbv2.Status_RESERVATION_REFUSED,
		pbv2.Status_RESOURCE_LIMIT_EXCEEDED,
		pbv2.Status_PERMISSION_DENIED,
		pbv2.Status_NO_RESERVATION,
		pbv2.Status_MALFORMED_MESSAGE:

		responseStatus = requestStatusRejected
	case pbv2.Status_UNEXPECTED_MESSAGE, pbv2.Status_CONNECTION_FAILED:
		responseStatus = requestStatusError
	case pbv2.Status_OK:
		responseStatus = requestStatusOK
	default:
	}

	return responseStatus
}

func getRejectionReason(status pbv2.Status) string {
	reason := "unknown"
	switch status {
	case pbv2.Status_RESERVATION_REFUSED:
		reason = "ip constraint violation"
	case pbv2.Status_RESOURCE_LIMIT_EXCEEDED:
		reason = "resource limit exceeded"
	case pbv2.Status_PERMISSION_DENIED:
		reason = "permission denied"
	case pbv2.Status_NO_RESERVATION:
		reason = "no reservation"
	case pbv2.Status_MALFORMED_MESSAGE:
		reason = "malformed message"
	default:
	}

	return reason
}
