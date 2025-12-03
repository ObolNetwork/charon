// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"slices"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/bcast"
	"github.com/obolnetwork/charon/dkg/pedersen"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
)

// ReplaceOperatorConfig contains the configuration for the replace-operator protocol.
// Typically populated from command line flags.
type ReplaceOperatorConfig struct {
	PrivateKeyPath   string
	LockFilePath     string
	ValidatorKeysDir string
	OutputDir        string
	NewENR           string
	OldENR           string
}

// RunReplaceOperatorProtocol runs the replace-operator DKG protocol.
func RunReplaceOperatorProtocol(ctx context.Context, config ReplaceOperatorConfig, dkgConfig Config) error {
	return RunProtocol(ctx,
		newReplaceOperatorProtocol(config),
		config.LockFilePath,
		config.PrivateKeyPath,
		config.ValidatorKeysDir,
		dkgConfig)
}

type replaceOperatorProtocol struct {
	outputDir      string
	newENR         string
	oldENR         string
	replacingIndex int
	newLockENRs    []string
	config         *pedersen.Config
	board          *pedersen.Board
}

var _ Protocol = (*replaceOperatorProtocol)(nil)

func newReplaceOperatorProtocol(config ReplaceOperatorConfig) *replaceOperatorProtocol {
	return &replaceOperatorProtocol{
		outputDir: config.OutputDir,
		newENR:    config.NewENR,
		oldENR:    config.OldENR,
	}
}

func (p *replaceOperatorProtocol) GetPeers(lock *cluster.Lock) ([]p2p.Peer, error) {
	// Replace the old operator with the new operator at the same index position.
	// This maintains share index consistency - the new operator inherits the position.
	peers, err := lock.Peers()
	if err != nil {
		return nil, err
	}

	// Find and store the index of the operator being replaced
	p.replacingIndex = slices.IndexFunc(lock.Operators, func(op cluster.Operator) bool {
		return op.ENR == p.oldENR
	})
	if p.replacingIndex == -1 {
		return nil, errors.New("old operator not found in lock")
	}

	newRec, err := enr.Parse(p.newENR)
	if err != nil {
		return nil, errors.Wrap(err, "parse enr")
	}

	// Create new peer at the same index as the old operator
	newPeer, err := p2p.NewPeerFromENR(newRec, p.replacingIndex)
	if err != nil {
		return nil, errors.Wrap(err, "new peer from enr")
	}

	// Build the peer list: keep all continuing operators at their original indices,
	// and place the new operator at the replacing index
	newPeers := make([]p2p.Peer, len(peers))
	copy(newPeers, peers)
	newPeers[p.replacingIndex] = newPeer

	// Build allENRs for the final cluster lock
	for i, op := range lock.Operators {
		if i == p.replacingIndex {
			p.newLockENRs = append(p.newLockENRs, p.newENR)
		} else {
			p.newLockENRs = append(p.newLockENRs, op.ENR)
		}
	}

	return newPeers, nil
}

func (p *replaceOperatorProtocol) PostInit(ctx context.Context, pctx *ProtocolContext) error {
	pctx.SigExchanger = newExchanger(pctx.ThisNode, pctx.ThisNodeIdx.PeerIdx, pctx.PeerIDs, []sigType{sigLock}, pctx.Config.Timeout)
	pctx.Caster = bcast.New(pctx.ThisNode, pctx.PeerIDs, pctx.ENRPrivateKey)
	pctx.NodeSigCaster = newNodeSigBcast(pctx.Peers, pctx.ThisNodeIdx, pctx.Caster)

	// For replace operator: identify the old and new peer IDs at the replacement position.
	// The old operator is being removed (OldPeers), the new operator is being added (NewPeers).
	// Since they occupy the same index position, this is a one-for-one swap.
	// Note: replacingIndex was already calculated and validated in GetPeers.
	allPeers, err := pctx.Lock.Peers()
	if err != nil {
		return err
	}

	oldPeerID := allPeers[p.replacingIndex].ID
	newPeerID := pctx.Peers[p.replacingIndex].ID

	reshareConfig := pedersen.NewReshareConfig(len(pctx.Lock.Validators), pctx.Lock.Threshold, []peer.ID{newPeerID}, []peer.ID{oldPeerID})
	p.config = pedersen.NewConfig(pctx.ThisPeerID, pctx.PeerMap, pctx.Lock.Threshold, pctx.Lock.DefinitionHash, pctx.Config.Timeout/6, reshareConfig)
	p.board = pedersen.NewBoard(ctx, pctx.ThisNode, p.config, pctx.Caster)

	return nil
}

func (p *replaceOperatorProtocol) Steps(pctx *ProtocolContext) []ProtocolStep {
	return []ProtocolStep{
		&reshareProtocolStep{config: p.config, board: p.board},
		&updateLockProtocolStep{threshold: pctx.Lock.Threshold, operators: p.newLockENRs},
		&updateNodeSignaturesProtocolStep{},
		&writeArtifactsProtocolStep{outputDir: p.outputDir},
	}
}
