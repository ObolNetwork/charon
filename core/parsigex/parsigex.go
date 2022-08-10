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

package parsigex

import (
	"context"
	"io"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/p2p"
)

const protocolID = "/charon/parsigex/1.0.0"

func NewParSigEx(tcpNode host.Host, sendFunc p2p.SendFunc, peerIdx int, peers []peer.ID, verifyFunc func(context.Context, core.Duty, core.PubKey, core.ParSignedData) error) *ParSigEx {
	parSigEx := &ParSigEx{
		tcpNode:    tcpNode,
		sendFunc:   sendFunc,
		peerIdx:    peerIdx,
		peers:      peers,
		verifyFunc: verifyFunc,
	}
	parSigEx.tcpNode.SetStreamHandler(protocolID, parSigEx.handle)

	return parSigEx
}

// ParSigEx exchanges partially signed duty data sets.
// It ensures that all partial signatures are persisted by all peers.
type ParSigEx struct {
	tcpNode    host.Host
	sendFunc   p2p.SendFunc
	peerIdx    int
	peers      []peer.ID
	verifyFunc func(context.Context, core.Duty, core.PubKey, core.ParSignedData) error
	subs       []func(context.Context, core.Duty, core.ParSignedDataSet) error
}

func (m *ParSigEx) handle(s network.Stream) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	ctx = log.WithTopic(ctx, "parsigex")
	ctx = log.WithCtx(ctx, z.Str("peer", p2p.PeerName(s.Conn().RemotePeer())))
	defer cancel()
	defer s.Close()

	b, err := io.ReadAll(s)
	if err != nil {
		log.Error(ctx, "Read proto bytes", err)
		return
	}

	pb := new(pbv1.ParSigExMsg)
	if err := proto.Unmarshal(b, pb); err != nil {
		log.Error(ctx, "Unmarshal parsigex proto", err)
		return
	}

	duty := core.DutyFromProto(pb.Duty)
	ctx = log.WithCtx(ctx, z.Any("duty", duty))

	set, err := core.ParSignedDataSetFromProto(duty.Type, pb.DataSet)
	if err != nil {
		log.Error(ctx, "Convert parsigex proto", err)
		return
	}

	var span trace.Span
	ctx, span = core.StartDutyTrace(ctx, duty, "core/parsigex.Handle")
	defer span.End()

	// Verify partial signature
	for pubkey, data := range set {
		if err = m.verifyFunc(ctx, duty, pubkey, data); err != nil {
			log.Error(ctx, "Peer exchanged invalid partial signature", err, z.Str("peer", p2p.PeerName(s.Conn().RemotePeer())))
			return
		}
	}

	for _, sub := range m.subs {
		err := sub(ctx, duty, set)
		if err != nil {
			log.Error(ctx, "Subscribe error", err)
		}
	}
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

	for i, p := range m.peers {
		// Don't send to self
		if i == m.peerIdx {
			continue
		}

		if err := m.sendFunc(ctx, m.tcpNode, protocolID, p, &msg); err != nil {
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

// NewEth2Verifier returns a verifyFunc instance which is responsible to verify the given partial signatures.
func NewEth2Verifier(eth2Svc eth2client.Service, pubSharesByKey map[core.PubKey]map[int]*bls_sig.PublicKey) (func(context.Context, core.Duty, core.PubKey, core.ParSignedData) error, error) {
	eth2Cl, ok := eth2Svc.(signing.Eth2Provider)
	if !ok {
		return nil, errors.New("invalid eth2 service")
	}

	return func(ctx context.Context, duty core.Duty, pubkey core.PubKey, data core.ParSignedData) error {
		pubshares, ok := pubSharesByKey[pubkey]
		if !ok {
			return errors.New("invalid pubkey")
		}

		pubshare, ok := pubshares[data.ShareIdx]
		if !ok {
			return errors.New("invalid shareIdx")
		}

		switch duty.Type {
		case core.DutyAttester:
			att, ok := data.SignedData.(core.Attestation)
			if !ok {
				return errors.New("invalid attestation")
			}

			return signing.VerifyAttestation(ctx, eth2Cl, pubshare, &att.Attestation)
		case core.DutyProposer:
			block, ok := data.SignedData.(core.VersionedSignedBeaconBlock)
			if !ok {
				return errors.New("invalid block")
			}

			return signing.VerifyBlock(ctx, eth2Cl, pubshare, &block.VersionedSignedBeaconBlock)
		case core.DutyRandao:
			randao, ok := data.SignedData.(core.Signature)
			if !ok {
				return errors.New("invalid randao")
			}

			return signing.VerifyRandao(ctx, eth2Cl, pubshare, randao.ToETH2(), eth2p0.Slot(duty.Slot))
		case core.DutyBuilderProposer:
			blindedBlock, ok := data.SignedData.(core.VersionedSignedBlindedBeaconBlock)
			if !ok {
				return errors.New("invalid blinded block")
			}

			return signing.VerifyBlindedBlock(ctx, eth2Cl, pubshare, &blindedBlock.VersionedSignedBlindedBeaconBlock)
		case core.DutyBuilderRegistration:
			registration, ok := data.SignedData.(core.VersionedSignedValidatorRegistration)
			if !ok {
				return errors.New("invalid builder registration")
			}

			return signing.VerifyValidatorRegistration(ctx, eth2Cl, pubshare, &registration.VersionedSignedValidatorRegistration)
		case core.DutyExit:
			exit, ok := data.SignedData.(core.SignedVoluntaryExit)
			if !ok {
				return errors.New("invalid voluntary exit")
			}

			return signing.VerifyVoluntaryExit(ctx, eth2Cl, pubshare, &exit.SignedVoluntaryExit)
		default:
			return errors.New("unknown duty type")
		}
	}, nil
}
