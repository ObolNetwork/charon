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
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	libp2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/dkg/sync"
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

type Config struct {
	DefFile string
	DataDir string
	P2P     p2p.Config
	Log     log.Config

	TestDef     *cluster.Definition
	TestSigning bool
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

	if err := log.InitLogger(conf.Log); err != nil {
		return err
	}

	def, err := loadDefinition(conf)
	if err != nil {
		return err
	}

	if err = checkWrites(conf.DataDir); err != nil {
		return err
	}

	network, err := forkVersionToNetwork(def.ForkVersion)
	if err != nil {
		return err
	}

	peers, err := def.Peers()
	if err != nil {
		return err
	}

	defHash, err := def.HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "hash definition")
	}
	clusterID := base64.StdEncoding.EncodeToString(defHash[:])

	key, err := p2p.LoadPrivKey(conf.DataDir)
	if err != nil {
		return err
	}

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

	log.Info(ctx, "Connecting to peers...", z.Str("definition_hash", clusterID))

	// Improve UX of "context cancelled" errors when sync fails.
	ctx = withCtxErr(ctx, "p2p connection failed, please retry DKG")

	stopSync, err := startSyncProtocol(ctx, tcpNode, key, defHash, peerIds, cancel)
	if err != nil {
		return err
	}

	log.Info(ctx, "Starting DKG ceremony")

	var shares []share
	switch def.DKGAlgorithm {
	case "keycast":
		tp := keycastP2P{
			tcpNode:   tcpNode,
			peers:     peers,
			clusterID: clusterID,
		}

		shares, err = runKeyCast(ctx, def, tp, nodeIdx.PeerIdx, crand.Reader)
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

	dvs, err := dvsFromShares(shares)
	if err != nil {
		return err
	}

	lock := cluster.Lock{
		Definition: def,
		Validators: dvs,
	}

	lockHash, err := lock.HashTreeRoot()
	if err != nil {
		return err
	}

	depositDataMsgs, err := getDepositDataMsgs(shares, def.WithdrawalAddress, network)
	if err != nil {
		return err
	}

	pubkeyToPubshares := make(map[core.PubKey]map[int]*bls_sig.PublicKey)
	for _, s := range shares {
		pubkey, err := tblsconv.KeyToCore(s.PubKey)
		if err != nil {
			return err
		}

		pubkeyToPubshares[pubkey] = s.PublicShares
	}
	ex := newExchanger(tcpNode, nodeIdx.PeerIdx, peerIds, def.NumValidators, newDKGVerifier(pubkeyToPubshares, lockHash[:], depositDataMsgs))

	// Sign, exchange and aggregate Lock Hash signatures
	aggSig, err := signAndAggLockHash(ctx, shares, lockHash[:], nodeIdx, ex)
	if err != nil {
		return err
	}
	lock.SignatureAggregate = aggSig
	log.Debug(ctx, "Aggregated lock hash signatures")

	set, err := signDepositData(shares, nodeIdx.ShareIdx, depositDataMsgs)
	if err != nil {
		return err
	}

	// Sign, exchange and aggregate Deposit Data signatures
	aggSigDepositData, err := signAndAggDepositData(ctx, ex, set, depositDataMsgs)
	if err != nil {
		return err
	}
	log.Debug(ctx, "Aggregated deposit data signatures")

	if err = stopSync(ctx); err != nil {
		return errors.Wrap(err, "sync shutdown")
	}

	// Write keystores, deposit data and cluster lock files after exchange of partial signatures in order
	// to prevent partial data writes in case of peer connection lost

	if err := writeKeystores(conf.DataDir, shares); err != nil {
		return err
	}
	log.Debug(ctx, "Saved keyshares to disk")

	if err = writeLock(conf.DataDir, lock); err != nil {
		return err
	}
	log.Debug(ctx, "Saved lock file to disk")

	if err := writeDepositData(aggSigDepositData, def.WithdrawalAddress, network, conf.DataDir); err != nil {
		return err
	}
	log.Debug(ctx, "Saved deposit data file to disk")

	log.Info(ctx, "Successfully completed DKG ceremony 🎉")

	return nil
}

// setupP2P returns a started libp2p tcp node and a shutdown function.
func setupP2P(ctx context.Context, key *ecdsa.PrivateKey, p2pConf p2p.Config, peers []p2p.Peer, lockHashHex string) (host.Host, func(), error) {
	localEnode, db, err := p2p.NewLocalEnode(p2pConf, key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to open enode")
	}

	bootnodes, err := p2p.NewUDPBootnodes(ctx, p2pConf, peers, localEnode.ID(), lockHashHex)
	if err != nil {
		return nil, nil, errors.Wrap(err, "new bootnodes")
	}

	udpNode, err := p2p.NewUDPNode(p2pConf, localEnode, key, bootnodes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "")
	}

	relays, err := p2p.NewRelays(p2pConf, bootnodes)
	if err != nil {
		return nil, nil, err
	}

	tcpNode, err := p2p.NewTCPNode(p2pConf, key, p2p.NewOpenGater(), udpNode, peers, relays)
	if err != nil {
		return nil, nil, errors.Wrap(err, "")
	}

	for _, relay := range relays {
		go func(relay p2p.Peer) {
			err := p2p.NewRelayReserver(tcpNode, relay)(ctx)
			if err != nil {
				log.Error(ctx, "Reserve relay error", err)
			}
		}(relay)
	}

	return tcpNode, func() {
		db.Close()
		udpNode.Close()
		_ = tcpNode.Close()
	}, nil
}

// startSyncProtocol sets up a sync protocol server and clients for each peer and returns a shutdown function
// when all peers are connected.
func startSyncProtocol(ctx context.Context, tcpNode host.Host, key *ecdsa.PrivateKey, defHash [32]byte, peerIDs []peer.ID,
	onFailure func(),
) (func(context.Context) error, error) {
	// Sign definition hash with charon-enr-private-key
	priv, err := libp2pcrypto.UnmarshalSecp256k1PrivateKey(crypto.FromECDSA(key))
	if err != nil {
		return nil, errors.Wrap(err, "convert key")
	}

	hashSig, err := priv.Sign(defHash[:])
	if err != nil {
		return nil, errors.Wrap(err, "sign definition hash")
	}

	server := sync.NewServer(tcpNode, len(peerIDs)-1, defHash[:])
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

	for _, client := range clients {
		err := client.AwaitConnected(ctx)
		if err != nil {
			return nil, err
		}
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

// signAndAggLockHash returns aggregated signature after signing, exchange and aggregation of partial signatures of lock hash.
func signAndAggLockHash(ctx context.Context, shares []share, lockHash []byte, nodeIdx cluster.NodeIdx, ex *exchanger) ([]byte, error) {
	sigLockHash, err := signLockHash(lockHash, nodeIdx.ShareIdx, shares)
	if err != nil {
		return nil, err
	}

	peerSigs, err := ex.exchange(ctx, sigLock, sigLockHash)
	if err != nil {
		return nil, err
	}

	pubkeyToShares := make(map[core.PubKey]share)
	for _, sh := range shares {
		pk, err := tblsconv.KeyToCore(sh.PubKey)
		if err != nil {
			return nil, err
		}

		pubkeyToShares[pk] = sh
	}

	aggSigLockHash, aggPkLockHash, err := aggLockHashSig(peerSigs, pubkeyToShares)
	if err != nil {
		return nil, err
	}

	verified, err := tbls.Scheme().VerifyMultiSignature(aggPkLockHash, lockHash, aggSigLockHash)
	if err != nil {
		return nil, errors.Wrap(err, "verify multisignature")
	} else if !verified {
		return nil, errors.New("invalid lock hash aggregated signature")
	}

	sigBytes, err := aggSigLockHash.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "marshal binary aggSigLockHash")
	}

	return sigBytes, nil
}

// signAndAggDepositData returns aggregated signatures per DV after signing, exchange and aggregation of partial signatures.
func signAndAggDepositData(ctx context.Context, ex *exchanger, set core.ParSignedDataSet, msgs map[core.PubKey][]byte) (map[core.PubKey]*bls_sig.Signature, error) {
	peerSigs, err := ex.exchange(ctx, sigDepositData, set)
	if err != nil {
		return nil, err
	}

	aggSigDepositData, err := aggDepositDataSigs(peerSigs)
	if err != nil {
		return nil, err
	}

	for pk, sig := range aggSigDepositData {
		pubkey, err := tblsconv.KeyFromCore(pk)
		if err != nil {
			return nil, err
		}
		ok, err := tbls.Verify(pubkey, msgs[pk], sig)
		if err != nil {
			return nil, err
		} else if !ok {
			return nil, errors.New("invalid deposit data aggregated signature")
		}
	}

	return aggSigDepositData, nil
}

// aggLockHashSig returns the aggregated multi signature of the lock hash
// signed by all the distributed validator group private keys.
func aggLockHashSig(data map[core.PubKey][]core.ParSignedData, shares map[core.PubKey]share) (*bls_sig.MultiSignature, *bls_sig.MultiPublicKey, error) {
	var (
		sigs    []*bls_sig.Signature
		pubkeys []*bls_sig.PublicKey
	)
	for pk, psigs := range data {
		for _, s := range psigs {
			sig, err := tblsconv.SigFromCore(s.Signature())
			if err != nil {
				return nil, nil, errors.Wrap(err, "signature from core")
			}

			sigs = append(sigs, sig)

			pubshare := shares[pk].PublicShares[s.ShareIdx]
			pubkeys = append(pubkeys, pubshare)
		}
	}

	// Full BLS Signature Aggregation
	aggSig, err := tbls.Scheme().AggregateSignatures(sigs...)
	if err != nil {
		return nil, nil, errors.Wrap(err, "bls aggregate Signatures")
	}

	// Aggregate Public Keys to verify aggregated signature
	aggPubKey, err := tbls.Scheme().AggregatePublicKeys(pubkeys...)
	if err != nil {
		return nil, nil, errors.Wrap(err, "bls aggregate Public Keys")
	}

	return aggSig, aggPubKey, nil
}

// signLockHash returns a partially signed dataset containing signatures of the lock hash.
func signLockHash(lockHash []byte, shareIdx int, shares []share) (core.ParSignedDataSet, error) {
	set := make(core.ParSignedDataSet)
	for _, share := range shares {
		pk, err := tblsconv.KeyToCore(share.PubKey)
		if err != nil {
			return nil, err
		}

		secret, err := tblsconv.ShareToSecret(share.SecretShare)
		if err != nil {
			return nil, err
		}

		sig, err := tbls.Sign(secret, lockHash)
		if err != nil {
			return nil, err
		}

		set[pk] = core.NewPartialSignature(tblsconv.SigToCore(sig), shareIdx)
	}

	return set, nil
}

// getDepositDataMsgs returns deposit data msgs to be signed.
func getDepositDataMsgs(shares []share, withdrawalAddr string, network string) (map[core.PubKey][]byte, error) {
	withdrawalAddr, err := checksumAddr(withdrawalAddr)
	if err != nil {
		return nil, err
	}

	msgs := make(map[core.PubKey][]byte)
	for _, share := range shares {
		pubkey, err := tblsconv.KeyToETH2(share.PubKey)
		if err != nil {
			return nil, err
		}

		pk, err := tblsconv.KeyToCore(share.PubKey)
		if err != nil {
			return nil, err
		}

		msg, err := deposit.GetMessageSigningRoot(pubkey, withdrawalAddr, network)
		if err != nil {
			return nil, err
		}
		msgs[pk] = msg[:]
	}

	return msgs, nil
}

// signDepositData returns a partially signed dataset containing signatures of the deposit data signing root.
func signDepositData(shares []share, shareIdx int, msgs map[core.PubKey][]byte) (core.ParSignedDataSet, error) {
	set := make(core.ParSignedDataSet)
	for _, share := range shares {
		pk, err := tblsconv.KeyToCore(share.PubKey)
		if err != nil {
			return nil, err
		}

		secret, err := tblsconv.ShareToSecret(share.SecretShare)
		if err != nil {
			return nil, err
		}

		sig, err := tbls.Sign(secret, msgs[pk])
		if err != nil {
			return nil, err
		}

		set[pk] = core.NewPartialSignature(tblsconv.SigToCore(sig), shareIdx)
	}

	return set, nil
}

// aggDepositDataSigs returns the threshold aggregated signatures of the deposit data per DV.
func aggDepositDataSigs(data map[core.PubKey][]core.ParSignedData) (map[core.PubKey]*bls_sig.Signature, error) {
	resp := make(map[core.PubKey]*bls_sig.Signature)

	for pk, psigsData := range data {
		var psigs []*bls_sig.PartialSignature
		for _, s := range psigsData {
			sig, err := tblsconv.SigFromCore(s.Signature())
			if err != nil {
				return nil, errors.Wrap(err, "signature from core")
			}

			psigs = append(psigs, &bls_sig.PartialSignature{
				Identifier: byte(s.ShareIdx),
				Signature:  sig.Value,
			})
		}

		// Aggregate signatures per DV
		asig, err := tbls.Aggregate(psigs)
		if err != nil {
			return nil, err
		}
		resp[pk] = asig
	}

	return resp, nil
}

func checksumAddr(a string) (string, error) {
	if !common.IsHexAddress(a) {
		return "", errors.New("invalid address")
	}

	return common.HexToAddress(a).Hex(), nil
}

// dvsFromShares returns the shares as a slice of cluster distributed validator types.
func dvsFromShares(shares []share) ([]cluster.DistValidator, error) {
	var dvs []cluster.DistValidator
	for _, s := range shares {
		msg, err := msgFromShare(s)
		if err != nil {
			return nil, err
		}

		dvs = append(dvs, cluster.DistValidator{
			PubKey:    fmt.Sprintf("%#x", msg.PubKey),
			PubShares: msg.PubShares,
		})
	}

	return dvs, nil
}

func forkVersionToNetwork(forkVersion string) (string, error) {
	switch forkVersion {
	case "0x00001020":
		return "prater", nil
	case "0x70000069":
		return "kiln", nil
	case "0x80000069":
		return "ropsten", nil
	case "0x00000064":
		return "gnosis", nil
	case "0x00000000":
		return "mainnet", nil
	default:
		return "", errors.New("invalid fork version")
	}
}

// withCtxErr returns a copy of the context that wraps the context.Canceled with
// the provided error.
func withCtxErr(ctx context.Context, wrapMsg string) context.Context {
	return ctxWrap{Context: ctx, wrapMsg: wrapMsg}
}

type ctxWrap struct {
	context.Context
	wrapMsg string
}

func (c ctxWrap) Err() error {
	err := c.Context.Err()
	if err == nil {
		return nil
	}

	return errors.Wrap(err, c.wrapMsg)
}
