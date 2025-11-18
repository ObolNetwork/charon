// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"encoding/json"
	"os"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth1wrap"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/bcast"
	"github.com/obolnetwork/charon/dkg/share"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
)

const (
	enrPrivateKeyFile   = "charon-enr-private-key"
	validatorKeysSubDir = "validator_keys"
	clusterLockFile     = "cluster-lock.json"
)

// Protocol is a generic interface for DKG protocols such as add/remove operators.
type Protocol interface {
	// GetPeers returns the peers participating in the protocol.
	// Typically, this is all peers in the cluster lock.
	GetPeers(*cluster.Lock) ([]p2p.Peer, error)

	// PostInit is called after the protocol context has been initialized but before any steps are run.
	// It can be used to set up any protocol-specific state in the context, or p2p services.
	PostInit(context.Context, *ProtocolContext) error

	// Steps returns the steps of the protocol, where each step is an action.
	// The steps are run sequentially, with a synchronization point between each step.
	Steps(*ProtocolContext) []ProtocolStep
}

// ProtocolStep is a single step in a DKG protocol.
type ProtocolStep interface {
	Run(context.Context, *ProtocolContext) error
}

// ProtocolContext is mutable context propagated across protocol steps.
type ProtocolContext struct {
	// The fields populated by the protocol runnner, before PostInit is called.
	Config         Config
	PrivateKeyPath string
	Lock           *cluster.Lock
	Shares         []share.Share // May be nil if validator_keys dir does not exist.
	ETH1Client     eth1wrap.EthClientRunner
	ENRPrivateKey  *k1.PrivateKey
	ThisPeerID     peer.ID
	ThisNodeIdx    cluster.NodeIdx
	ThisNode       host.Host
	Peers          []p2p.Peer // Initially populated from GetPeers result.
	PeerIDs        []peer.ID
	PeerMap        map[peer.ID]cluster.NodeIdx

	// The fields populated by the protocol in PostInit, before any steps are run.
	// Note that any fields of the structure can be modified by the protocol in PostInit.
	SigExchanger  *exchanger
	Caster        *bcast.Component
	NodeSigCaster *nodeSigBcast
}

// RunProtocol runs the given DKG protocol with the provided configuration.
func RunProtocol(ctx context.Context, protocol Protocol, lockFilePath, privateKeyPath, validatorKeysDir string, config Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	lock, err := LoadAndVerifyClusterLock(ctx, lockFilePath, config.ExecutionEngineAddr, config.NoVerify)
	if err != nil {
		return errors.Wrap(err, "load cluster lock")
	}

	protocolCtx := &ProtocolContext{
		Config:         config,
		Lock:           lock,
		PrivateKeyPath: privateKeyPath,
	}

	if _, err := os.Stat(validatorKeysDir); err == nil || !os.IsNotExist(err) {
		secrets, err := LoadSecrets(validatorKeysDir)
		if err != nil {
			return errors.Wrap(err, "load secrets")
		}

		if len(secrets) != len(lock.Validators) {
			return errors.New("number of private key shares does not match number of validators in cluster lock",
				z.Int("numKeyShares", len(secrets)),
				z.Int("numValidators", len(lock.Validators)))
		}

		log.Info(ctx, "Loaded private key shares", z.Int("numKeys", len(secrets)))

		protocolCtx.Shares = make([]share.Share, len(secrets))
		for i := range protocolCtx.Shares {
			protocolCtx.Shares[i] = share.Share{
				PubKey:      tbls.PublicKey(lock.Validators[i].PubKey),
				SecretShare: secrets[i],
			}
		}

		log.Debug(ctx, "Private key shares loaded", z.Int("numShares", len(protocolCtx.Shares)))
	}

	protocolCtx.ETH1Client = eth1wrap.NewDefaultEthClientRunner(config.ExecutionEngineAddr)
	go protocolCtx.ETH1Client.Run(ctx)

	enrPrivateKey, err := LoadPrivKey(privateKeyPath)
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

	if err := verifyPeerDuplicates(peers); err != nil {
		return err
	}

	thisNode, shutdown, err := setupP2P(ctx, enrPrivateKey, config, peers, lock.DefinitionHash)
	if err != nil {
		return err
	}
	defer shutdown()

	logPeerSummary(ctx, thisPeerID, peers, lock.Operators)

	protocolCtx.Peers = peers
	protocolCtx.PeerIDs, protocolCtx.PeerMap = buildPeerMap(peers)
	protocolCtx.ThisNodeIdx = protocolCtx.PeerMap[thisPeerID]
	protocolCtx.ThisNode = thisNode

	if err := protocol.PostInit(ctx, protocolCtx); err != nil {
		return errors.Wrap(err, "protocol post init")
	}

	log.Info(ctx, "Waiting to connect to all peers...")

	nextStepSync, stopSync, err := startSyncProtocol(ctx, thisNode, enrPrivateKey, lock.DefinitionHash, protocolCtx.PeerIDs, cancel, TestConfig{}, config.Nickname)
	if err != nil {
		return err
	}

	for _, step := range protocol.Steps(protocolCtx) {
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

// LoadAndVerifyClusterLock loads the cluster lock from disk and verifies its hashes and signatures.
func LoadAndVerifyClusterLock(ctx context.Context, lockFilePath, executionEngineAddr string, noVerify bool) (*cluster.Lock, error) {
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

	eth1Cl := eth1wrap.NewDefaultEthClientRunner(executionEngineAddr)
	go eth1Cl.Run(ctx)

	if err := lock.VerifyHashes(); err != nil && !noVerify {
		return nil, errors.Wrap(err, "verify cluster lock hashes (run with --no-verify to bypass verification at own risk)")
	} else if err != nil && noVerify {
		log.Warn(ctx, "Ignoring failed cluster lock hashes verification due to --no-verify flag", err)
	}

	if err := lock.VerifySignatures(eth1Cl); err != nil && !noVerify {
		return nil, errors.Wrap(err, "verify cluster lock signatures (run with --no-verify to bypass verification at own risk)")
	} else if err != nil && noVerify {
		log.Warn(ctx, "Ignoring failed cluster lock signature verification due to --no-verify flag", err)
	}

	return &lock, nil
}

// LoadSecrets loads the private key shares from the validator keys subdirectory in the given data directory.
func LoadSecrets(validatorKeysDir string) ([]tbls.PrivateKey, error) {
	var secrets []tbls.PrivateKey

	privateKeyFiles, err := keystore.LoadFilesUnordered(validatorKeysDir)
	if err != nil {
		return nil, errors.Wrap(err, "load private key share", z.Str("path", validatorKeysDir))
	}

	secrets, err = privateKeyFiles.SequencedKeys()
	if err != nil {
		return nil, errors.Wrap(err, "order private key shares")
	}

	return secrets, nil
}

// LoadPrivKey loads a secp256k1 private key from the given file path.
func LoadPrivKey(privateKeyPath string) (*k1.PrivateKey, error) {
	key, err := k1util.Load(privateKeyPath)
	if err != nil {
		return nil, errors.Wrap(err, "load priv key")
	}

	return key, nil
}

// LoadMyENR loads private key and returns the ENR.
func LoadMyENR(privateKeyPath string) (string, error) {
	key, err := LoadPrivKey(privateKeyPath)
	if err != nil {
		return "", err
	}

	rec, err := enr.New(key)
	if err != nil {
		return "", errors.Wrap(err, "create ENR")
	}

	return rec.String(), nil
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

func verifyPeerDuplicates(peers []p2p.Peer) error {
	peerSet := make(map[peer.ID]struct{})

	for _, p := range peers {
		if _, exists := peerSet[p.ID]; exists {
			return errors.New("duplicate peer ID found", z.Str("peerID", p.ID.String()))
		}

		peerSet[p.ID] = struct{}{}
	}

	return nil
}
