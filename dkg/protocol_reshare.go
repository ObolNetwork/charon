// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/bcast"
	"github.com/obolnetwork/charon/dkg/pedersen"
	"github.com/obolnetwork/charon/p2p"
)

// ReshareConfig is the configuration for the reshare DKG protocol (same operators set).
type ReshareConfig struct {
	DKGConfig        Config
	PrivateKeyPath   string
	LockFilePath     string
	ValidatorKeysDir string
	OutputDir        string
	// ProposerConfigFile is the current proposer config file, its content is carried over into the new lock.
	ProposerConfigFile string
	// OverridesFile is the builder registration overrides file feeding genesis when ProposerConfigFile is absent.
	OverridesFile string
}

// RunReshareProtocol runs the reshare DKG protocol (same operators set).
func RunReshareProtocol(ctx context.Context, config ReshareConfig) error {
	return RunProtocol(ctx,
		newReshareProtocol(config),
		config.LockFilePath,
		config.PrivateKeyPath,
		config.ValidatorKeysDir,
		config.DKGConfig)
}

type reshareProtocol struct {
	outputDir          string
	proposerConfigFile string
	overridesFile      string
	config             *pedersen.Config
	board              *pedersen.Board
}

var _ Protocol = (*reshareProtocol)(nil)

func newReshareProtocol(config ReshareConfig) *reshareProtocol {
	return &reshareProtocol{
		outputDir:          config.OutputDir,
		proposerConfigFile: config.ProposerConfigFile,
		overridesFile:      config.OverridesFile,
	}
}

func (*reshareProtocol) GetPeers(lock *cluster.Lock) ([]p2p.Peer, error) {
	return lock.Peers()
}

func (p *reshareProtocol) PostInit(ctx context.Context, pctx *ProtocolContext) error {
	sigEx, err := newExchanger(pctx.ThisNode, pctx.ThisNodeIdx.PeerIdx, pctx.PeerIDs, pctx.PeerMap, []sigType{sigLock}, pctx.Config.Timeout)
	if err != nil {
		return err
	}

	pctx.SigExchanger = sigEx
	// Bind broadcasts to the lock hash since it changes with every cluster mutation,
	// preventing replay of messages from previous ceremonies of the same cluster.
	pctx.Caster = bcast.New(pctx.ThisNode, pctx.PeerIDs, pctx.ENRPrivateKey, pctx.Lock.LockHash)
	pctx.NodeSigCaster = newNodeSigBcast(pctx.Peers, pctx.ThisNodeIdx, pctx.Caster, nodeSigMsgID)

	err = initProposerConfig(ctx, pctx, p.proposerConfigFile, p.overridesFile, false)
	if err != nil {
		return err
	}

	pedersenReshareConfig := pedersen.NewReshareConfig(len(pctx.Lock.Validators), pctx.Lock.Threshold, nil, nil)
	p.config = pedersen.NewConfig(pctx.ThisPeerID, pctx.PeerMap, pctx.Lock.Threshold, pctx.Lock.DefinitionHash, pctx.Config.Timeout/6, pedersenReshareConfig)
	p.board = pedersen.NewBoard(ctx, pctx.ThisNode, p.config, pctx.Caster)

	return nil
}

func (p *reshareProtocol) Steps(*ProtocolContext) []ProtocolStep {
	return []ProtocolStep{
		&agreeProposerConfigProtocolStep{},
		&reshareProtocolStep{config: p.config, board: p.board},
		&updateLockProtocolStep{},
		&updateNodeSignaturesProtocolStep{},
		&writeArtifactsProtocolStep{outputDir: p.outputDir},
	}
}
