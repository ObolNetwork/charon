// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth1wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/bcast"
	"github.com/obolnetwork/charon/dkg/pedersen"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
)

const (
	enrPrivateKeyFile   = "charon-enr-private-key"
	validatorKeysSubDir = "validator_keys"
	clusterLockFile     = "cluster-lock.json"
)

// Protocol is a generic interface for DKG protocols.
type Protocol interface {
	GetPeers(*cluster.Lock) ([]p2p.Peer, error)
	PostInit(context.Context, *ProtocolContext) error
	Steps() []ProtocolStep
}

// ProtocolStep is a single step in a DKG protocol.
type ProtocolStep interface {
	Run(context.Context, *ProtocolContext) error
}

// ProtocolContext is mutable context propagated across protocol steps.
type ProtocolContext struct {
	Config        Config
	ETH1Client    eth1wrap.EthClientRunner
	ENRPrivateKey *k1.PrivateKey
	ThisPeerID    peer.ID
	ThisNodeIdx   cluster.NodeIdx
	ThisNode      host.Host
	PeerIDs       []peer.ID
	PeerMap       map[peer.ID]cluster.NodeIdx
	SigExchanger  *exchanger
	Caster        *bcast.Component
	NodeSigCaster *nodeSigBcast
	Lock          *cluster.Lock
	Shares        []*pedersen.Share
}

func RunProtocol(ctx context.Context, protocol Protocol, config Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	lock, err := loadAndVerifyClusterLock(ctx, config.DataDir, config)
	if err != nil {
		return errors.Wrap(err, "load cluster lock")
	}

	protocolCtx := &ProtocolContext{
		Config: config,
		Lock:   lock,
	}

	validatorKeysDir := filepath.Join(config.DataDir, validatorKeysSubDir)
	if _, err := os.Stat(validatorKeysDir); err == nil || !os.IsNotExist(err) {
		secrets, err := loadSecrets(ctx, config.DataDir)
		if err != nil {
			return errors.Wrap(err, "load secrets")
		}

		if len(secrets) != len(lock.Validators) {
			return errors.New("number of private key shares does not match number of validators in cluster lock",
				z.Int("numKeyShares", len(secrets)),
				z.Int("numValidators", len(lock.Validators)))
		}

		log.Info(ctx, "Loaded private key shares", z.Int("numKeys", len(secrets)))

		protocolCtx.Shares = make([]*pedersen.Share, len(secrets))
		for i := range protocolCtx.Shares {
			protocolCtx.Shares[i] = &pedersen.Share{
				PubKey:      tbls.PublicKey(lock.Validators[i].PubKey),
				SecretShare: secrets[i],
			}
		}
	}

	protocolCtx.ETH1Client = eth1wrap.NewDefaultEthClientRunner(config.ExecutionEngineAddr)
	go protocolCtx.ETH1Client.Run(ctx)

	enrPrivateKey, err := p2p.LoadPrivKey(config.DataDir)
	if err != nil {
		return err
	}

	protocolCtx.ENRPrivateKey = enrPrivateKey

	thisPeerID, err := p2p.PeerIDFromKey(enrPrivateKey.PubKey())
	if err != nil {
		return err
	}

	protocolCtx.ThisPeerID = thisPeerID

	peers, err := protocol.GetPeers(lock)
	if err != nil {
		return err
	}

	thisNode, shutdown, err := setupP2P(ctx, enrPrivateKey, config, peers, lock.DefinitionHash)
	if err != nil {
		return err
	}
	defer shutdown()

	protocolCtx.PeerIDs, protocolCtx.PeerMap = buildPeerMap(peers)
	protocolCtx.ThisNodeIdx = protocolCtx.PeerMap[thisPeerID]
	protocolCtx.ThisNode = thisNode

	protocolCtx.SigExchanger = newExchanger(thisNode, protocolCtx.ThisNodeIdx.PeerIdx, protocolCtx.PeerIDs, []sigType{
		sigLock,
		sigDepositData,
		sigValidatorRegistration,
	}, config.Timeout)
	protocolCtx.Caster = bcast.New(thisNode, protocolCtx.PeerIDs, enrPrivateKey)
	protocolCtx.NodeSigCaster = newNodeSigBcast(peers, protocolCtx.ThisNodeIdx, protocolCtx.Caster)

	logPeerSummary(ctx, thisPeerID, peers, lock.Operators)

	if err := protocol.PostInit(ctx, protocolCtx); err != nil {
		return errors.Wrap(err, "protocol post init")
	}

	log.Info(ctx, "Waiting to connect to all peers...")

	nextStepSync, stopSync, err := startSyncProtocol(ctx, thisNode, enrPrivateKey, lock.DefinitionHash, protocolCtx.PeerIDs, cancel, TestConfig{})
	if err != nil {
		return err
	}

	for _, step := range protocol.Steps() {
		if err := step.Run(ctx, protocolCtx); err != nil {
			return err
		}

		if err := nextStepSync(ctx); err != nil {
			return errors.Wrap(err, "sync next step")
		}
	}

	if err = stopSync(ctx); err != nil {
		return errors.Wrap(err, "sync shutdown")
	}

	time.Sleep(config.ShutdownDelay)

	return nil
}

func loadAndVerifyClusterLock(ctx context.Context, dataDir string, conf Config) (*cluster.Lock, error) {
	lockFilePath := filepath.Join(dataDir, clusterLockFile)

	b, err := os.ReadFile(lockFilePath)
	if err != nil {
		return nil, errors.Wrap(err, "read cluster-lock.json", z.Str("path", lockFilePath))
	}

	var lock cluster.Lock
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, errors.Wrap(err, "unmarshal cluster-lock.json", z.Str("path", lockFilePath))
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	eth1Cl := eth1wrap.NewDefaultEthClientRunner(conf.ExecutionEngineAddr)
	go eth1Cl.Run(ctx)

	if err := lock.VerifyHashes(); err != nil && !conf.NoVerify {
		return nil, errors.Wrap(err, "cluster lock hashes verification failed. Run with --no-verify to bypass verification at own risk")
	} else if err != nil && conf.NoVerify {
		log.Warn(ctx, "Ignoring failed cluster lock hashes verification due to --no-verify flag", err)
	}

	if err := lock.VerifySignatures(eth1Cl); err != nil && !conf.NoVerify {
		return nil, errors.Wrap(err, "cluster lock signature verification failed. Run with --no-verify to bypass verification at own risk")
	} else if err != nil && conf.NoVerify {
		log.Warn(ctx, "Ignoring failed cluster lock signature verification due to --no-verify flag", err)
	}

	return &lock, nil
}

func loadSecrets(ctx context.Context, dataDir string) ([]tbls.PrivateKey, error) {
	var secrets []tbls.PrivateKey

	keyStorePath := filepath.Join(dataDir, validatorKeysSubDir)
	log.Info(ctx, "Loading keystore", z.Str("path", keyStorePath))

	privateKeyFiles, err := keystore.LoadFilesUnordered(keyStorePath)
	if err != nil {
		return nil, errors.Wrap(err, "cannot load private key share", z.Str("path", keyStorePath))
	}

	secrets, err = privateKeyFiles.SequencedKeys()
	if err != nil {
		return nil, errors.Wrap(err, "order private key shares")
	}

	return secrets, nil
}

func buildPeerMap(peers []p2p.Peer) ([]peer.ID, map[peer.ID]cluster.NodeIdx) {
	peerIDs := make([]peer.ID, len(peers))
	peerMap := make(map[peer.ID]cluster.NodeIdx)

	for i, p := range peers {
		peerIDs[i] = p.ID
		peerMap[p.ID] = cluster.NodeIdx{
			PeerIdx:  i,
			ShareIdx: i + 1,
		}
	}

	return peerIDs, peerMap
}
