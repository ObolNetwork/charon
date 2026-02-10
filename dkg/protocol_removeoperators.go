// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	"github.com/obolnetwork/charon/p2p"
)

// RemoveOperatorsConfig contains the configuration for the remove-operators protocol.
// Typically populated from command line flags.
type RemoveOperatorsConfig struct {
	PrivateKeyPath    string
	LockFilePath      string
	ValidatorKeysDir  string
	OutputDir         string
	RemovingENRs      []string
	ParticipatingENRs []string
	NewThreshold      int
}

// RunRemoveOperatorsProtocol runs the remove-operators DKG protocol.
func RunRemoveOperatorsProtocol(ctx context.Context, config RemoveOperatorsConfig, dkgConfig Config) error {
	return RunProtocol(ctx,
		newRemoveOperatorsProtocol(config),
		config.LockFilePath,
		config.PrivateKeyPath,
		config.ValidatorKeysDir,
		dkgConfig)
}

type removeOperatorsProtocol struct {
	outputDir     string
	oldENRs       []string
	operators     []string
	participating []string
	newThreshold  int
	oldNode       bool
	config        *pedersen.Config
	board         *pedersen.Board
}

var _ Protocol = (*removeOperatorsProtocol)(nil)

func newRemoveOperatorsProtocol(config RemoveOperatorsConfig) *removeOperatorsProtocol {
	return &removeOperatorsProtocol{
		outputDir:     config.OutputDir,
		oldENRs:       config.RemovingENRs,
		newThreshold:  config.NewThreshold,
		participating: config.ParticipatingENRs,
		oldNode:       false,
	}
}

func (p *removeOperatorsProtocol) GetPeers(lock *cluster.Lock) ([]p2p.Peer, error) {
	allPeers, err := lock.Peers()
	if err != nil {
		return nil, err
	}

	enrIndexMap := make(map[string]int, len(lock.Operators))
	for i, op := range lock.Operators {
		enrIndexMap[op.ENR] = i
	}

	peers := make([]p2p.Peer, 0)

	if len(p.participating) > 0 {
		for _, enr := range p.participating {
			index, found := enrIndexMap[enr]
			if !found {
				return nil, errors.New("participating ENR not found among lock operators", z.Str("enr", enr))
			}

			peers = append(peers, allPeers[index])
		}
	} else {
		for index, op := range lock.Operators {
			found := slices.Contains(p.oldENRs, op.ENR)
			if found {
				continue
			}

			peers = append(peers, allPeers[index])
		}
	}

	return peers, nil
}

func (p *removeOperatorsProtocol) PostInit(ctx context.Context, pctx *ProtocolContext) error {
	allPeers, err := pctx.Lock.Peers()
	if err != nil {
		return err
	}

	_, peerMap := buildPeerMap(allPeers)

	newN := len(allPeers) - len(p.oldENRs)
	newT := newN - (newN-1)/3

	if p.newThreshold != 0 {
		if p.newThreshold >= newN || p.newThreshold < newT {
			return errors.New("new-threshold is invalid", z.Int("recommendedThreshold", newT))
		}
	} else {
		p.newThreshold = newT
	}

	oldPeerIDs := make([]peer.ID, 0)
	newPeerIDs := make([]peer.ID, 0)

	for i, op := range pctx.Lock.Operators {
		isOld := slices.Contains(p.oldENRs, op.ENR)
		if isOld {
			oldPeerIDs = append(oldPeerIDs, allPeers[i].ID)
		} else {
			newPeerIDs = append(newPeerIDs, allPeers[i].ID)
			p.operators = append(p.operators, op.ENR)
		}

		if pctx.ThisPeerID == allPeers[i].ID && isOld {
			p.oldNode = true
		}

		participating := slices.ContainsFunc(pctx.Peers, func(p p2p.Peer) bool {
			return p.ID == allPeers[i].ID
		})
		if !participating {
			delete(peerMap, allPeers[i].ID)
		}
	}

	// The broadcaster is created for all participating nodes, because it is used by the board and the node signature caster.
	pctx.Caster = bcast.New(pctx.ThisNode, pctx.PeerIDs, pctx.ENRPrivateKey)
	pctx.NodeSigCaster = newNodeSigBcast(pctx.Peers, pctx.ThisNodeIdx, pctx.Caster)

	if !p.oldNode {
		// SigExchanger is only created for nodes remaining in the cluster, because old nodes do not participate in signing.
		nodeIdx := slices.Index(newPeerIDs, pctx.ThisPeerID)
		pctx.ThisNodeIdx = cluster.NodeIdx{
			PeerIdx:  nodeIdx,
			ShareIdx: peerMap[pctx.ThisPeerID].ShareIdx,
		}
		pctx.SigExchanger = newExchanger(pctx.ThisNode, nodeIdx, newPeerIDs, []sigType{sigLock}, pctx.Config.Timeout)
	}

	reshareConfig := pedersen.NewReshareConfig(len(pctx.Lock.Validators), p.newThreshold, nil, oldPeerIDs)
	p.config = pedersen.NewConfig(pctx.ThisPeerID, peerMap, pctx.Lock.Threshold, pctx.Lock.DefinitionHash, pctx.Config.Timeout/6, reshareConfig)
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
