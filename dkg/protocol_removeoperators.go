// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"slices"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/bcast"
	"github.com/obolnetwork/charon/dkg/pedersen"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
)

// RemoveOperatorsConfig contains the configuration for the remove-operators protocol.
// Typically populated from command line flags.
type RemoveOperatorsConfig struct {
	OutputDir    string
	OldENRs      []string
	NewThreshold int
}

// RunRemoveOperatorsProtocol runs the remove-operators DKG protocol.
func RunRemoveOperatorsProtocol(ctx context.Context, config RemoveOperatorsConfig, dkgConfig Config) error {
	return RunProtocol(ctx, newRemoveOperatorsProtocol(config), dkgConfig)
}

type removeOperatorsProtocol struct {
	outputDir    string
	oldENRs      []string
	operators    []string
	newThreshold int
	oldNode      bool
	config       *pedersen.Config
	board        *pedersen.Board
}

var _ Protocol = (*removeOperatorsProtocol)(nil)

func newRemoveOperatorsProtocol(config RemoveOperatorsConfig) *removeOperatorsProtocol {
	return &removeOperatorsProtocol{
		outputDir:    config.OutputDir,
		oldENRs:      config.OldENRs,
		newThreshold: config.NewThreshold,
		oldNode:      true,
	}
}

func (*removeOperatorsProtocol) GetPeers(lock *cluster.Lock) ([]p2p.Peer, error) {
	return lock.Peers()
}

func (p *removeOperatorsProtocol) PostInit(ctx context.Context, pctx *ProtocolContext) error {
	newN := len(pctx.PeerIDs) - len(p.oldENRs)
	newT := newN - (newN-1)/3

	if p.newThreshold != 0 {
		if p.newThreshold >= newN || p.newThreshold < newT {
			return errors.New("new-threshold is invalid", z.Int("recommendedThreshold", newT))
		}
	} else {
		p.newThreshold = newT
	}

	newPeerIDs := make([]peer.ID, 0)
	oldPeerIDs := make([]peer.ID, 0)

	for i, operator := range pctx.Lock.Operators {
		if slices.Contains(p.oldENRs, operator.ENR) {
			oldPeerIDs = append(oldPeerIDs, pctx.PeerIDs[i])

			continue
		}

		record, err := enr.Parse(operator.ENR)
		if err != nil {
			return errors.Wrap(err, "decode enr", z.Str("enr", operator.ENR))
		}

		peer, err := p2p.NewPeerFromENR(record, i)
		if err != nil {
			return err
		}

		newPeerIDs = append(newPeerIDs, peer.ID)
		p.operators = append(p.operators, operator.ENR)
	}

	nodeIdx := slices.IndexFunc(newPeerIDs, func(id peer.ID) bool {
		return id == pctx.ThisPeerID
	})

	// The broadcaster is created for all nodes, because it is used by the board and the node signature caster.
	// Unfortunately, the broadcaster does not support flexible peer lists to change recipients on the fly.
	pctx.Caster = bcast.New(pctx.ThisNode, pctx.PeerIDs, pctx.ENRPrivateKey)
	pctx.NodeSigCaster = newNodeSigBcast(pctx.Peers, pctx.ThisNodeIdx, pctx.Caster)

	if nodeIdx >= 0 {
		// SigExchanger is only created for nodes remaining in the cluster, because old nodes do not participate in signing.
		pctx.SigExchanger = newExchanger(pctx.ThisNode, nodeIdx, newPeerIDs, []sigType{sigLock}, pctx.Config.Timeout)
		pctx.ThisNodeIdx = cluster.NodeIdx{PeerIdx: nodeIdx, ShareIdx: nodeIdx + 1}
		p.oldNode = false
	}

	reshareConfig := pedersen.NewReshareConfig(len(pctx.Lock.Validators), p.newThreshold, nil, oldPeerIDs)
	p.config = pedersen.NewConfig(pctx.ThisPeerID, pctx.PeerMap, pctx.Lock.Threshold, pctx.Lock.DefinitionHash, pctx.Config.Timeout/12, reshareConfig)
	p.board = pedersen.NewBoard(ctx, pctx.ThisNode, p.config, pctx.Caster)

	return nil
}

func (p *removeOperatorsProtocol) Steps(*ProtocolContext) []ProtocolStep {
	if p.oldNode {
		return []ProtocolStep{
			&reshareProtocolStep{config: p.config, board: p.board},
			&noopProtocolStep{},
			&ignoreNodeSignaturesProtocolStep{},
			&noopProtocolStep{},
		}
	}

	return []ProtocolStep{
		&reshareProtocolStep{config: p.config, board: p.board},
		&updateLockProtocolStep{threshold: p.newThreshold, operators: p.operators},
		&updateNodeSignaturesProtocolStep{},
		&writeArtifactsProtocolStep{outputDir: p.outputDir},
	}
}
