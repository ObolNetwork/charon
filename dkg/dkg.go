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

package dkg

import (
	"context"
	"fmt"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/dkg/sync"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/eth2util/keymanager"
	"github.com/obolnetwork/charon/p2p"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
	tblsconv2 "github.com/obolnetwork/charon/tbls/v2/tblsconv"
)

type Config struct {
	DefFile        string
	KeymanagerAddr string
	NoVerify       bool
	DataDir        string
	P2P            p2p.Config
	Log            log.Config

	TestDef          *cluster.Definition
	TestSyncCallback func(connected int, id peer.ID)
}

// Run executes a dkg ceremony and writes secret share keystore and cluster lock files as output to disk.
func Run(ctx context.Context, conf Config) (err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ctx = log.WithTopic(ctx, "dkg")
	defer func() {
		if err != nil {
			log.Error(ctx, "Fatal error", err)
		}
	}()

	version.LogInfo(ctx, "Charon DKG starting")

	def, err := loadDefinition(ctx, conf)
	if err != nil {
		return err
	}

	// Check if keymanager address is reachable.
	if conf.KeymanagerAddr != "" {
		cl := keymanager.New(conf.KeymanagerAddr)
		if err = cl.VerifyConnection(ctx); err != nil {
			return errors.Wrap(err, "verify keymanager address")
		}
	}

	if err = checkWrites(conf.DataDir); err != nil {
		return err
	}

	network, err := eth2util.ForkVersionToNetwork(def.ForkVersion)
	if err != nil {
		return err
	}

	peers, err := def.Peers()
	if err != nil {
		return err
	}

	clusterID := fmt.Sprintf("%#x", def.DefinitionHash)

	key, err := p2p.LoadPrivKey(conf.DataDir)
	if err != nil {
		return err
	}

	pID, err := p2p.PeerIDFromKey(key.PubKey())
	if err != nil {
		return err
	}

	log.Info(ctx, "Starting local P2P networking peer", z.Str("local_peer", p2p.PeerName(pID)))

	tcpNode, shutdown, err := setupP2P(ctx, key, conf.P2P, peers, clusterID)
	if err != nil {
		return err
	}
	defer shutdown()

	nodeIdx, err := def.NodeIdx(tcpNode.ID())
	if err != nil {
		return errors.Wrap(err, "private key not matching definition file")
	}

	peerIds, err := def.PeerIDs()
	if err != nil {
		return errors.Wrap(err, "get peer IDs")
	}

	ex := newExchanger(tcpNode, nodeIdx.PeerIdx, peerIds, def.NumValidators)

	// Register Frost libp2p handlers
	peerMap := make(map[uint32]peer.ID)
	for _, p := range peers {
		nodeIdx, err := def.NodeIdx(p.ID)
		if err != nil {
			return err
		}
		peerMap[uint32(nodeIdx.ShareIdx)] = p.ID
	}
	tp := newFrostP2P(ctx, tcpNode, peerMap, clusterID)

	log.Info(ctx, "Waiting to connect to all peers...")

	// Improve UX of "context cancelled" errors when sync fails.
	ctx = errors.WithCtxErr(ctx, "p2p connection failed, please retry DKG")

	stopSync, err := startSyncProtocol(ctx, tcpNode, key, def.DefinitionHash, peerIds, cancel, conf.TestSyncCallback)
	if err != nil {
		return err
	}

	log.Info(ctx, "All peers connected, starting DKG ceremony")

	var shares []share
	switch def.DKGAlgorithm {
	case "keycast":
		tp := keycastP2P{
			tcpNode:   tcpNode,
			peers:     peers,
			clusterID: clusterID,
		}

		shares, err = runKeyCast(ctx, def, tp, nodeIdx.PeerIdx)
		if err != nil {
			return err
		}
	case "default", "frost":
		shares, err = runFrostParallel(ctx, tp, uint32(def.NumValidators), uint32(len(peerMap)),
			uint32(def.Threshold), uint32(nodeIdx.ShareIdx), clusterID)
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported dkg algorithm")
	}

	// Sign, exchange and aggregate Lock Hash signatures
	lock, err := signAndAggLockHash(ctx, shares, def, nodeIdx, ex)
	if err != nil {
		return err
	}
	if !conf.NoVerify {
		if err := lock.VerifySignatures(); err != nil {
			return errors.Wrap(err, "invalid lock file")
		}
	}
	log.Debug(ctx, "Aggregated lock hash signatures")

	// Sign, exchange and aggregate Deposit Data signatures
	pubkeys, depositDataSigs, err := signAndAggDepositData(ctx, ex, shares, lock.WithdrawalAddresses(), network, nodeIdx)
	if err != nil {
		return err
	}
	log.Debug(ctx, "Aggregated deposit data signatures")

	if err = stopSync(ctx); err != nil {
		return errors.Wrap(err, "sync shutdown")
	}

	// Write keystores, deposit data and cluster lock files after exchange of partial signatures in order
	// to prevent partial data writes in case of peer connection lost

	if conf.KeymanagerAddr != "" { // Save to keymanager
		if err = writeKeysToKeymanager(ctx, conf.KeymanagerAddr, shares); err != nil {
			return err
		}
		log.Debug(ctx, "Imported keyshares to keymanager", z.Str("keymanager_address", conf.KeymanagerAddr))
	} else { // Else save to disk
		if err = writeKeysToDisk(conf.DataDir, shares); err != nil {
			return err
		}
		log.Debug(ctx, "Saved keyshares to disk")
	}

	if err = writeLock(conf.DataDir, lock); err != nil {
		return err
	}
	log.Debug(ctx, "Saved lock file to disk")

	if err := writeDepositData(pubkeys, depositDataSigs, lock.WithdrawalAddresses(), network, conf.DataDir); err != nil {
		return err
	}
	log.Debug(ctx, "Saved deposit data file to disk")

	log.Info(ctx, "Successfully completed DKG ceremony 🎉")

	return nil
}

// setupP2P returns a started libp2p tcp node and a shutdown function.
func setupP2P(ctx context.Context, key *k1.PrivateKey, p2pConf p2p.Config, peers []p2p.Peer, lockHashHex string) (host.Host, func(), error) {
	var peerIDs []peer.ID
	for _, p := range peers {
		peerIDs = append(peerIDs, p.ID)
	}

	if err := p2p.VerifyP2PKey(peers, key); err != nil {
		return nil, nil, err
	}

	relays, err := p2p.NewRelays(ctx, p2pConf.Relays, lockHashHex)
	if err != nil {
		return nil, nil, err
	}

	connGater, err := p2p.NewConnGater(peerIDs, relays)
	if err != nil {
		return nil, nil, err
	}

	tcpNode, err := p2p.NewTCPNode(ctx, p2pConf, key, connGater)
	if err != nil {
		return nil, nil, err
	}

	p2p.RegisterConnectionLogger(ctx, tcpNode, peerIDs)

	for _, relay := range relays {
		go func(relay *p2p.MutablePeer) {
			err := p2p.NewRelayReserver(tcpNode, relay)(ctx)
			if err != nil {
				log.Error(ctx, "Reserve relay error", err)
			}
		}(relay)
	}

	go p2p.NewRelayRouter(tcpNode, peers, relays)(ctx)

	return tcpNode, func() {
		_ = tcpNode.Close()
	}, nil
}

// startSyncProtocol sets up a sync protocol server and clients for each peer and returns a shutdown function
// when all peers are connected.
func startSyncProtocol(ctx context.Context, tcpNode host.Host, key *k1.PrivateKey, defHash []byte, peerIDs []peer.ID,
	onFailure func(), testCallback func(connected int, id peer.ID),
) (func(context.Context) error, error) {
	// Sign definition hash with charon-enr-private-key
	// Note: libp2p signing does another hash of the defHash.
	hashSig, err := ((*libp2pcrypto.Secp256k1PrivateKey)(key)).Sign(defHash)
	if err != nil {
		return nil, errors.Wrap(err, "sign definition hash")
	}

	server := sync.NewServer(tcpNode, len(peerIDs)-1, defHash)
	server.Start(ctx)

	var clients []*sync.Client
	for _, pID := range peerIDs {
		if tcpNode.ID() == pID {
			continue
		}

		ctx := log.WithCtx(ctx, z.Str("peer", p2p.PeerName(pID)))
		client := sync.NewClient(tcpNode, pID, hashSig)
		clients = append(clients, client)

		go func() {
			err := client.Run(ctx)
			if err != nil && !errors.Is(err, context.Canceled) { // Only log and fail if this peer errored.
				log.Error(ctx, "Sync failed to peer", err)
				onFailure()
			}
		}()
	}

	// Check if all clients are connected.
	for {
		// Return if there is a context error.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		var connectedCount int
		for _, client := range clients {
			if client.IsConnected() {
				connectedCount++
			}
		}

		if testCallback != nil {
			testCallback(connectedCount, tcpNode.ID())
		}

		// Break if all clients are connected
		if len(clients) == connectedCount {
			break
		}

		// Sleep for 100ms to let clients connect with each other.
		time.Sleep(time.Millisecond * 100)
	}

	// Disable reconnecting clients to other peer's server once all clients are connected.
	for _, client := range clients {
		client.DisableReconnect()
	}

	err = server.AwaitAllConnected(ctx)
	if err != nil {
		return nil, err
	}

	// Shutdown function stops all clients and server
	return func(ctx context.Context) error {
		for _, client := range clients {
			err := client.Shutdown(ctx)
			if err != nil {
				return err
			}
		}

		return server.AwaitAllShutdown(ctx)
	}, nil
}

// signAndAggLockHash returns cluster lock file with aggregated signature after signing, exchange and aggregation of partial signatures.
func signAndAggLockHash(ctx context.Context, shares []share, def cluster.Definition, nodeIdx cluster.NodeIdx, ex *exchanger) (cluster.Lock, error) {
	dvs, err := dvsFromShares(shares)
	if err != nil {
		return cluster.Lock{}, err
	}

	lock := cluster.Lock{
		Definition: def,
		Validators: dvs,
	}

	lock, err = lock.SetLockHash()
	if err != nil {
		return cluster.Lock{}, err
	}

	lockHashSig, err := signLockHash(nodeIdx.ShareIdx, shares, lock.LockHash)
	if err != nil {
		return cluster.Lock{}, err
	}

	peerSigs, err := ex.exchange(ctx, sigLock, lockHashSig)
	if err != nil {
		return cluster.Lock{}, err
	}

	pubkeyToShares := make(map[core.PubKey]share)
	for _, sh := range shares {
		pk, err := core.PubKeyFromBytes(sh.PubKey[:])
		if err != nil {
			return cluster.Lock{}, err
		}

		pubkeyToShares[pk] = sh
	}

	aggSigLockHash, aggPkLockHash, err := aggLockHashSig(peerSigs, pubkeyToShares, lock.LockHash)
	if err != nil {
		return cluster.Lock{}, err
	}

	err = tblsv2.VerifyAggregate(aggPkLockHash, aggSigLockHash, lock.LockHash)
	if err != nil {
		return cluster.Lock{}, errors.Wrap(err, "verify multisignature")
	}

	lock.SignatureAggregate = aggSigLockHash[:]

	return lock, nil
}

// signAndAggDepositData returns aggregated signatures per DV after signing, exchange and aggregation of partial signatures.
func signAndAggDepositData(ctx context.Context, ex *exchanger, shares []share, withdrawalAddresses []string, network string, nodeIdx cluster.NodeIdx) ([]eth2p0.BLSPubKey, []eth2p0.BLSSignature, error) {
	parSig, msgs, err := signDepositData(shares, nodeIdx.ShareIdx, withdrawalAddresses, network)
	if err != nil {
		return nil, nil, err
	}

	peerSigs, err := ex.exchange(ctx, sigDepositData, parSig)
	if err != nil {
		return nil, nil, err
	}

	aggSigDepositData, err := aggDepositDataSigs(peerSigs, shares, msgs)
	if err != nil {
		return nil, nil, err
	}

	for pk, sig := range aggSigDepositData {
		pk := pk
		sig := sig
		pkb, err := pk.Bytes()
		if err != nil {
			return nil, nil, errors.Wrap(err, "core bytes marshaling failure")
		}

		pubkey, err := tblsconv2.PubkeyFromBytes(pkb)
		if err != nil {
			return nil, nil, err
		}

		err = tblsv2.Verify(pubkey, msgs[pk], sig)
		if err != nil {
			return nil, nil, errors.Wrap(err, "invalid deposit data aggregated signature")
		}
	}

	var (
		pubkeys         []eth2p0.BLSPubKey
		depositDataSigs []eth2p0.BLSSignature
	)
	for _, sh := range shares {
		eth2Pk, err := tblsconv2.PubkeyToETH2(sh.PubKey)
		if err != nil {
			return nil, nil, err
		}

		corePk, err := core.PubKeyFromBytes(sh.PubKey[:])
		if err != nil {
			return nil, nil, err
		}

		pubkeys = append(pubkeys, eth2Pk)
		depositDataSigs = append(depositDataSigs, tblsconv2.SigToETH2(aggSigDepositData[corePk]))
	}

	return pubkeys, depositDataSigs, nil
}

// aggLockHashSig returns the aggregated multi signature of the lock hash
// signed by all the private key shares of all the distributed validators.
func aggLockHashSig(data map[core.PubKey][]core.ParSignedData, shares map[core.PubKey]share, hash []byte) (tblsv2.Signature, []tblsv2.PublicKey, error) {
	var (
		sigs    []tblsv2.Signature
		pubkeys []tblsv2.PublicKey
	)

	for pk, psigs := range data {
		pk := pk
		psigs := psigs
		for _, s := range psigs {
			sig, err := tblsconv2.SignatureFromBytes(s.Signature())
			if err != nil {
				return tblsv2.Signature{}, nil, errors.Wrap(err, "signature from bytes")
			}

			sh, ok := shares[pk]
			if !ok {
				// peerIdx is 0-indexed while shareIdx is 1-indexed
				return tblsv2.Signature{}, nil, errors.New("invalid pubkey in lock hash partial signature from peer",
					z.Int("peerIdx", s.ShareIdx-1), z.Str("pubkey", pk.String()))
			}

			pubshare, ok := sh.PublicShares[s.ShareIdx]
			if !ok {
				return tblsv2.Signature{}, nil, errors.New("invalid pubshare")
			}

			err = tblsv2.Verify(pubshare, hash, sig)
			if err != nil {
				return tblsv2.Signature{}, nil, errors.Wrap(err, "invalid lock hash partial signature from peer",
					z.Int("peerIdx", s.ShareIdx-1), z.Str("pubkey", pk.String()))
			}

			sigs = append(sigs, sig)
			pubkeys = append(pubkeys, pubshare)
		}
	}

	// Full BLS Signature Aggregation
	aggSig, err := tblsv2.Aggregate(sigs)
	if err != nil {
		return tblsv2.Signature{}, nil, errors.Wrap(err, "bls aggregate Signatures")
	}

	return aggSig, pubkeys, nil
}

// signLockHash returns a partially signed dataset containing signatures of the lock hash.
func signLockHash(shareIdx int, shares []share, hash []byte) (core.ParSignedDataSet, error) {
	set := make(core.ParSignedDataSet)
	for _, share := range shares {
		pk, err := core.PubKeyFromBytes(share.PubKey[:])
		if err != nil {
			return nil, err
		}

		sig, err := tblsv2.Sign(share.SecretShare, hash)
		if err != nil {
			return nil, err
		}

		set[pk] = core.NewPartialSignature(tblsconv2.SigToCore(sig), shareIdx)
	}

	return set, nil
}

// signDepositData returns a partially signed dataset containing signatures of the deposit data signing root.
func signDepositData(shares []share, shareIdx int, withdrawalAddresses []string, network string) (core.ParSignedDataSet, map[core.PubKey][]byte, error) {
	msgs := make(map[core.PubKey][]byte)
	set := make(core.ParSignedDataSet)
	for i, share := range shares {
		withdrawalHex, err := eth2util.ChecksumAddress(withdrawalAddresses[i])
		if err != nil {
			return nil, nil, err
		}
		pubkey, err := tblsconv2.PubkeyToETH2(share.PubKey)
		if err != nil {
			return nil, nil, err
		}

		pk, err := core.PubKeyFromBytes(share.PubKey[:])
		if err != nil {
			return nil, nil, err
		}

		msg, err := deposit.GetMessageSigningRoot(pubkey, withdrawalHex, network)
		if err != nil {
			return nil, nil, err
		}
		msgs[pk] = msg[:]

		sig, err := tblsv2.Sign(share.SecretShare, msg[:])
		if err != nil {
			return nil, nil, err
		}

		set[pk] = core.NewPartialSignature(tblsconv2.SigToCore(sig), shareIdx)
	}

	return set, msgs, nil
}

// aggDepositDataSigs returns the threshold aggregated signatures of the deposit data per DV.
func aggDepositDataSigs(data map[core.PubKey][]core.ParSignedData, shares []share, msgs map[core.PubKey][]byte) (map[core.PubKey]tblsv2.Signature, error) {
	pubkeyToPubShares := make(map[core.PubKey]map[int]tblsv2.PublicKey)
	for _, sh := range shares {
		pk, err := core.PubKeyFromBytes(sh.PubKey[:])
		if err != nil {
			return nil, err
		}

		pubkeyToPubShares[pk] = sh.PublicShares
	}

	resp := make(map[core.PubKey]tblsv2.Signature)

	for pk, psigsData := range data {
		pk := pk
		psigsData := psigsData
		psigs := make(map[int]tblsv2.Signature)
		for _, s := range psigsData {
			sig, err := tblsconv2.SignatureFromBytes(s.Signature())
			if err != nil {
				return nil, errors.Wrap(err, "signature from core")
			}

			pubshares, ok := pubkeyToPubShares[pk]
			if !ok {
				// peerIdx is 0-indexed while shareIdx is 1-indexed
				return nil, errors.New("invalid pubkey in deposit data partial signature from peer",
					z.Int("peerIdx", s.ShareIdx-1), z.Str("pubkey", pk.String()))
			}

			pubshare, ok := pubshares[s.ShareIdx]
			if !ok {
				return nil, errors.New("invalid pubshare")
			}

			err = tblsv2.Verify(pubshare, msgs[pk], sig)
			if err != nil {
				return nil, errors.New("invalid deposit data partial signature from peer",
					z.Int("peerIdx", s.ShareIdx-1), z.Str("pubkey", pk.String()))
			}

			psigs[s.ShareIdx] = sig
		}

		// Aggregate signatures per DV
		asig, err := tblsv2.ThresholdAggregate(psigs)
		if err != nil {
			return nil, err
		}
		resp[pk] = asig
	}

	return resp, nil
}

// dvsFromShares returns the shares as a slice of cluster distributed validator types.
func dvsFromShares(shares []share) ([]cluster.DistValidator, error) {
	var dvs []cluster.DistValidator
	for _, s := range shares {
		msg := msgFromShare(s)

		dvs = append(dvs, cluster.DistValidator{
			PubKey:    msg.PubKey,
			PubShares: msg.PubShares,
		})
	}

	return dvs, nil
}
