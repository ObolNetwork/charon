// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package parsigex

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/promauto"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
)

var setVerificationDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Namespace: "core",
	Subsystem: "parsigex",
	Name:      "set_verification_seconds",
	Help:      "Duration to verify all partial signatures in a received set, in seconds",
	Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
}, []string{"duty"})

const protocolID2 = "/charon/parsigex/2.0.0"

// Protocols returns the supported protocols of this package in order of precedence.
func Protocols() []protocol.ID {
	return []protocol.ID{protocolID2}
}

func NewParSigEx(p2pNode host.Host, sendFunc p2p.SendFunc, peerIdx int, peers []peer.ID,
	verifyFunc func(context.Context, peer.ID, core.Duty, core.PubKey, core.ParSignedData) error,
	gaterFunc core.DutyGaterFunc, p2pOpts ...p2p.SendRecvOption,
) *ParSigEx {
	parSigEx := &ParSigEx{
		p2pNode:    p2pNode,
		sendFunc:   sendFunc,
		peerIdx:    peerIdx,
		peers:      peers,
		verifyFunc: verifyFunc,
		gaterFunc:  gaterFunc,
	}

	newReq := func() proto.Message { return new(pbv1.ParSigExMsg) }
	p2p.RegisterHandler(
		"parsigex",
		p2pNode,
		protocolID2,
		newReq,
		parSigEx.handle,
		p2pOpts...,
	)

	return parSigEx
}

// ParSigEx exchanges partially signed duty data sets.
// It ensures that all partial signatures are persisted by all peers.
type ParSigEx struct {
	p2pNode    host.Host
	sendFunc   p2p.SendFunc
	peerIdx    int
	peers      []peer.ID
	verifyFunc func(context.Context, peer.ID, core.Duty, core.PubKey, core.ParSignedData) error
	gaterFunc  core.DutyGaterFunc
	subs       []func(context.Context, core.Duty, core.ParSignedDataSet) error
}

func (m *ParSigEx) handle(ctx context.Context, sender peer.ID, req proto.Message) (proto.Message, bool, error) {
	pb, ok := req.(*pbv1.ParSigExMsg)
	if !ok {
		return nil, false, errors.New("invalid request type")
	}

	if pb == nil || pb.GetDuty() == nil || pb.GetDataSet() == nil {
		return nil, false, errors.New("invalid parsigex msg fields", z.Any("msg", pb))
	}

	duty := core.DutyFromProto(pb.GetDuty())
	ctx = log.WithCtx(ctx, z.Any("duty", duty))

	if !m.gaterFunc(duty) {
		return nil, false, errors.New("invalid duty")
	}

	set, err := core.ParSignedDataSetFromProto(duty.Type, pb.GetDataSet())
	if err != nil {
		return nil, false, errors.Wrap(err, "convert parsigex proto")
	}

	if duty.Type == core.DutyProposer {
		var span trace.Span

		ctx, span = core.StartDutyTrace(ctx, duty, "core/parsigex.Handle")
		defer span.End()
	}

	// Verify partial signatures and record timing
	verifyStart := time.Now()

	for pubkey, data := range set {
		if err = m.verifyFunc(ctx, sender, duty, pubkey, data); err != nil {
			return nil, false, errors.Wrap(err, "invalid partial signature")
		}
	}

	setVerificationDuration.WithLabelValues(duty.Type.String()).Observe(time.Since(verifyStart).Seconds())

	for _, sub := range m.subs {
		// TODO(corver): Call this async
		err := sub(ctx, duty, set)
		if err != nil {
			log.Error(ctx, "Partial signature exchange subscriber encountered an error while processing the partial signature set", err)
		}
	}

	return nil, false, nil
}

// Broadcast broadcasts the partially signed duty data set to all peers.
func (m *ParSigEx) Broadcast(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
	ctx = log.WithTopic(ctx, "parsigex")

	pb, err := core.ParSignedDataSetToProto(set)
	if err != nil {
		return err
	}

	msg := pbv1.ParSigExMsg{
		Duty:    core.DutyToProto(duty),
		DataSet: pb,
	}

	topic := p2p.WithSendMetricTopic("parsigex_" + duty.Type.String())

	for i, p := range m.peers {
		// Don't send to self
		if i == m.peerIdx {
			continue
		}

		if err := m.sendFunc(ctx, m.p2pNode, protocolID2, p, &msg, topic); err != nil {
			return err
		}
	}

	return nil
}

// Subscribe registers a callback when a partially signed duty set
// is received from a peer. This is not thread safe, it must be called before starting to use parsigex.
func (m *ParSigEx) Subscribe(fn func(context.Context, core.Duty, core.ParSignedDataSet) error) {
	m.subs = append(m.subs, fn)
}

// VerifyPeerShareIdx checks that a partial signature comes from a known peer under that peer's own
// assigned share index, preventing a peer from replaying another peer's partial signature. peerMap
// maps each peer to its node index, so the check holds even when share indices are not contiguous
// (for example after operators have been removed).
func VerifyPeerShareIdx(peerMap map[peer.ID]cluster.NodeIdx, sender peer.ID, data core.ParSignedData) error {
	nodeIdx, ok := peerMap[sender]
	if !ok {
		return errors.New("partial signature from unknown peer", z.Str("peer", sender.String()))
	}

	if data.ShareIdx <= 0 || data.ShareIdx != nodeIdx.ShareIdx {
		return errors.New("partial signature share index does not match sender peer",
			z.Str("peer", sender.String()), z.Int("share_idx", data.ShareIdx), z.Int("expected_share_idx", nodeIdx.ShareIdx))
	}

	return nil
}

// NewEth2Verifier returns a partial signature verification function for core workflow eth2 signatures.
// Each partial signature is first bound to its authenticated sender via peerShareIdx: a peer may only
// contribute partial signatures under its own assigned share index. The signature is then verified
// cryptographically against the pubshare for that share index.
func NewEth2Verifier(eth2Cl eth2wrap.Client, pubSharesByKey map[core.PubKey]map[int]tbls.PublicKey, peerShareIdx map[peer.ID]cluster.NodeIdx) (func(context.Context, peer.ID, core.Duty, core.PubKey, core.ParSignedData) error, error) {
	return func(ctx context.Context, sender peer.ID, duty core.Duty, pubkey core.PubKey, data core.ParSignedData) error {
		if err := VerifyPeerShareIdx(peerShareIdx, sender, data); err != nil {
			return err
		}

		pubshares, ok := pubSharesByKey[pubkey]
		if !ok {
			return errors.New("unknown pubkey, not part of cluster lock")
		}

		pubshare, ok := pubshares[data.ShareIdx]
		if !ok {
			return errors.New("invalid shareIdx")
		}

		eth2Signed, ok := data.SignedData.(core.Eth2SignedData)
		if !ok {
			return errors.New("invalid eth2 signed data")
		}

		err := core.VerifyEth2SignedData(ctx, eth2Cl, eth2Signed, pubshare)
		if err != nil {
			return errors.Wrap(err, "invalid signature", z.Str("duty", duty.String()))
		}

		return nil
	}, nil
}
