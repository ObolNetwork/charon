// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/bcast"
	"github.com/obolnetwork/charon/dkg/pedersen"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
)

type addOperatorsProtocol struct {
	outputDir    string
	newENRs      []string
	newThreshold int
	allENRs      []string
	config       *pedersen.Config
	board        *pedersen.Board
}

var _ Protocol = (*addOperatorsProtocol)(nil)

func newAddOperatorsProtocol(config AddOperatorsConfig) *addOperatorsProtocol {
	return &addOperatorsProtocol{
		outputDir:    config.OutputDir,
		newENRs:      config.NewENRs,
		newThreshold: config.NewThreshold,
	}
}

func (p *addOperatorsProtocol) GetPeers(lock *cluster.Lock) ([]p2p.Peer, error) {
	// In add-operators protocol, both existing and new operators participate,
	// therefore we combine the peers from the existing lock with the new ENRs.
	peers, err := lock.Peers()
	if err != nil {
		return nil, err
	}

	// Add new operators to the peer list
	for i, newENR := range p.newENRs {
		rec, err := enr.Parse(newENR)
		if err != nil {
			return nil, errors.Wrap(err, "parse enr")
		}

		index := len(lock.Operators) + i

		newPeer, err := p2p.NewPeerFromENR(rec, index)
		if err != nil {
			return nil, errors.Wrap(err, "new peer from enr")
		}

		peers = append(peers, newPeer)
	}

	return peers, nil
}

func (p *addOperatorsProtocol) PostInit(ctx context.Context, pctx *ProtocolContext) error {
	newN := len(pctx.PeerIDs)
	newT := newN - (newN-1)/3

	if p.newThreshold != 0 {
		if p.newThreshold >= newN || p.newThreshold < newT {
			return errors.New("new-threshold is invalid", z.Int("recommendedThreshold", newT))
		}
	} else {
		p.newThreshold = newT
	}

	for _, operator := range pctx.Lock.Operators {
		p.allENRs = append(p.allENRs, operator.ENR)
	}

	p.allENRs = append(p.allENRs, p.newENRs...)

	pctx.SigExchanger = newExchanger(pctx.ThisNode, pctx.ThisNodeIdx.PeerIdx, pctx.PeerIDs, []sigType{sigLock}, pctx.Config.Timeout)
	pctx.Caster = bcast.New(pctx.ThisNode, pctx.PeerIDs, pctx.ENRPrivateKey)
	pctx.NodeSigCaster = newNodeSigBcast(pctx.Peers, pctx.ThisNodeIdx, pctx.Caster)

	newPeerIDs := pctx.PeerIDs[len(pctx.Lock.Operators):]
	reshareConfig := pedersen.NewReshareConfig(len(pctx.Lock.Validators), p.newThreshold, newPeerIDs, nil)
	p.config = pedersen.NewConfig(pctx.ThisPeerID, pctx.PeerMap, pctx.Lock.Threshold, pctx.Lock.DefinitionHash, reshareConfig)
	p.board = pedersen.NewBoard(ctx, pctx.ThisNode, p.config, pctx.Caster)

	return nil
}

func (p *addOperatorsProtocol) Steps(*ProtocolContext) []ProtocolStep {
	return []ProtocolStep{
		&reshareProtocolStep{config: p.config, board: p.board},
		&updateLockProtocolStep{threshold: p.newThreshold, operators: p.allENRs},
		&updateNodeSignaturesProtocolStep{},
		&writeArtifactsProtocolStep{outputDir: p.outputDir},
	}
}
