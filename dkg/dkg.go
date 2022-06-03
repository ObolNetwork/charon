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
	crand "crypto/rand"
	"fmt"
	"time"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/ethereum/go-ethereum/common"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
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
	ctx = log.WithTopic(ctx, "dkg")
	defer func() {
		if err != nil {
			log.Error(ctx, "Fatal run error", err)
		}
	}()

	if err := log.InitLogger(conf.Log); err != nil {
		return err
	}

	def, err := loadDefinition(conf)
	if err != nil {
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

	tcpNode, shutdown, err := setupP2P(ctx, conf.DataDir, conf.P2P, peers)
	if err != nil {
		return err
	}
	defer shutdown()

	nodeIdx, err := def.NodeIdx(tcpNode.ID())
	if err != nil {
		return err
	}

	defHash, err := def.HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "hash definition")
	}
	clusterID := fmt.Sprintf("%x", defHash[:])

	peerIds, err := def.PeerIDs()
	if err != nil {
		return errors.Wrap(err, "get peer IDs")
	}

	ex := newExchanger(tcpNode, nodeIdx.PeerIdx, peerIds, def.NumValidators)

	var shares []share
	switch def.DKGAlgorithm {
	case "default", "keycast":
		tp := keycastP2P{
			tcpNode:   tcpNode,
			peers:     peers,
			clusterID: clusterID,
		}

		shares, err = runKeyCast(ctx, def, tp, nodeIdx.PeerIdx, crand.Reader)
		if err != nil {
			return err
		}
	case "frost":
		// Construct peer map
		peerMap := make(map[uint32]peer.ID)
		for _, p := range peers {
			nodeIdx, err := def.NodeIdx(p.ID)
			if err != nil {
				return err
			}
			peerMap[uint32(nodeIdx.ShareIdx)] = p.ID
		}

		tp := newFrostP2P(ctx, tcpNode, peerMap, clusterID)

		log.Info(ctx, "Connecting to peers...")

		ctx, cancel, err := waitPeers(ctx, tcpNode, peers)
		if err != nil {
			return err
		}
		defer cancel()

		log.Info(ctx, "Starting Frost DKG ceremony")

		shares, err = runFrostParallel(ctx, tp, uint32(def.NumValidators), uint32(len(peerMap)),
			uint32(def.Threshold), uint32(nodeIdx.ShareIdx), clusterID)
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported dkg algorithm")
	}

	if err := writeKeystores(conf.DataDir, shares); err != nil {
		return err
	}
	log.Debug(ctx, "Saved keyshares to disk")

	// Sign, exchange and aggregate Lock Hash signatures
	lock, err := signAndAggLockHash(ctx, shares, def, nodeIdx, ex)
	if err != nil {
		return err
	}
	log.Debug(ctx, "Aggregated lock hash signatures")

	if err = writeLock(conf.DataDir, lock); err != nil {
		return err
	}
	log.Debug(ctx, "Saved lock file to disk")

	// Sign, exchange and aggregate Deposit Data signatures
	aggSigDepositData, err := signAndAggDepositData(ctx, ex, shares, def.WithdrawalAddress, network, nodeIdx)
	if err != nil {
		return err
	}
	log.Debug(ctx, "Aggregated deposit data signatures")

	if err := writeDepositData(aggSigDepositData, def.WithdrawalAddress, network, conf.DataDir); err != nil {
		return err
	}
	log.Debug(ctx, "Saved deposit data file to disk")

	log.Info(ctx, "Successfully completed DKG ceremony 🎉")

	return nil
}

// setupP2P returns a started libp2p tcp node and a shutdown function.
func setupP2P(ctx context.Context, datadir string, p2pConf p2p.Config, peers []p2p.Peer) (host.Host, func(), error) {
	key, err := p2p.LoadPrivKey(datadir)
	if err != nil {
		return nil, nil, err
	}

	localEnode, db, err := p2p.NewLocalEnode(p2pConf, key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to open enode")
	}

	bootnodes, err := p2p.NewUDPBootnodes(ctx, p2pConf, peers, localEnode.ID())
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

	// Register ping service handler
	_ = ping.NewPingService(tcpNode)

	return tcpNode, func() {
		db.Close()
		udpNode.Close()
		_ = tcpNode.Close()
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

	sigLockHash, err := signLockHash(lock, nodeIdx.ShareIdx, shares)
	if err != nil {
		return cluster.Lock{}, err
	}

	peerSigs, err := ex.exchange(ctx, dutyLock, sigLockHash)
	if err != nil {
		return cluster.Lock{}, err
	}

	pubkeyToShares := make(map[core.PubKey]share)
	for _, sh := range shares {
		pk, err := tblsconv.KeyToCore(sh.PubKey)
		if err != nil {
			return cluster.Lock{}, err
		}

		pubkeyToShares[pk] = sh
	}

	aggSigLockHash, aggPkLockHash, err := aggLockHashSig(peerSigs, pubkeyToShares, def.DKGAlgorithm)
	if err != nil {
		return cluster.Lock{}, err
	}

	msg, err := lock.HashTreeRoot()
	if err != nil {
		return cluster.Lock{}, err
	}

	verified, err := tbls.Scheme().VerifyMultiSignature(aggPkLockHash, msg[:], aggSigLockHash)
	if err != nil {
		return cluster.Lock{}, errors.Wrap(err, "verify multisignature")
	} else if !verified {
		return cluster.Lock{}, errors.New("invalid lock hash aggregated signature")
	}

	sigBytes, err := aggSigLockHash.MarshalBinary()
	if err != nil {
		return cluster.Lock{}, errors.Wrap(err, "marshal binary aggSigLockHash")
	}
	lock.SignatureAggregate = sigBytes

	return lock, nil
}

// signAndAggDepositData returns aggregated signatures per DV after signing, exchange and aggregation of partial signatures.
func signAndAggDepositData(ctx context.Context, ex *exchanger, shares []share, withdrawalAddr string, network string, nodeIdx cluster.NodeIdx) (map[core.PubKey]*bls_sig.Signature, error) {
	sigDepositData, msgs, err := signDepositData(shares, nodeIdx.ShareIdx, withdrawalAddr, network)
	if err != nil {
		return nil, err
	}

	peerSigs, err := ex.exchange(ctx, dutyDepositData, sigDepositData)
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
func aggLockHashSig(data map[core.PubKey][]core.ParSignedData, shares map[core.PubKey]share, dkgAlgo string) (*bls_sig.MultiSignature, *bls_sig.MultiPublicKey, error) {
	var (
		sigs    []*bls_sig.Signature
		pubkeys []*bls_sig.PublicKey
	)
	for pk, psigs := range data {
		for _, s := range psigs {
			sig, err := tblsconv.SigFromCore(s.Signature)
			if err != nil {
				return nil, nil, errors.Wrap(err, "signature from core")
			}

			sigs = append(sigs, sig)

			var pubshare *bls_sig.PublicKey
			switch dkgAlgo {
			case "keycast":
				pubshare = shares[pk].PublicShares[s.ShareIdx]
			case "frost":
				pubshare = shares[pk].PublicShares[s.ShareIdx]
			default:
				return nil, nil, errors.New("invalid dkg algo")
			}

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
func signLockHash(lock cluster.Lock, shareIdx int, shares []share) (core.ParSignedDataSet, error) {
	hash, err := lock.HashTreeRoot()
	if err != nil {
		return nil, errors.Wrap(err, "hash lock")
	}

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

		sig, err := tbls.Sign(secret, hash[:])
		if err != nil {
			return nil, err
		}

		sigBytes, err := sig.MarshalBinary()
		if err != nil {
			return nil, errors.Wrap(err, "marshal sig")
		}

		set[pk] = core.ParSignedData{
			Signature: sigBytes,
			ShareIdx:  shareIdx,
		}
	}

	return set, nil
}

// signDepositData returns a partially signed dataset containing signatures of the deposit data signing root.
func signDepositData(shares []share, shareIdx int, withdrawalAddr string, network string) (core.ParSignedDataSet, map[core.PubKey][]byte, error) {
	withdrawalAddr, err := checksumAddr(withdrawalAddr)
	if err != nil {
		return nil, nil, err
	}

	msgs := make(map[core.PubKey][]byte)
	set := make(core.ParSignedDataSet)
	for _, share := range shares {
		pubkey, err := tblsconv.KeyToETH2(share.PubKey)
		if err != nil {
			return nil, nil, err
		}

		pk, err := tblsconv.KeyToCore(share.PubKey)
		if err != nil {
			return nil, nil, err
		}

		msg, err := deposit.GetMessageSigningRoot(pubkey, withdrawalAddr, network)
		if err != nil {
			return nil, nil, err
		}
		msgs[pk] = msg[:]

		secret, err := tblsconv.ShareToSecret(share.SecretShare)
		if err != nil {
			return nil, nil, err
		}

		sig, err := tbls.Sign(secret, msg[:])
		if err != nil {
			return nil, nil, err
		}

		sigBytes, err := sig.MarshalBinary()
		if err != nil {
			return nil, nil, errors.Wrap(err, "marshal sig")
		}

		set[pk] = core.ParSignedData{
			Signature: sigBytes,
			ShareIdx:  shareIdx,
		}
	}

	return set, msgs, nil
}

// aggDepositDataSigs returns the threshold aggregated signatures of the deposit data per DV.
func aggDepositDataSigs(data map[core.PubKey][]core.ParSignedData) (map[core.PubKey]*bls_sig.Signature, error) {
	resp := make(map[core.PubKey]*bls_sig.Signature)

	for pk, psigsData := range data {
		var psigs []*bls_sig.PartialSignature
		for _, s := range psigsData {
			sig, err := tblsconv.SigFromCore(s.Signature)
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

// waitPeers blocks until all peers are connected or the context is cancelled.
func waitPeers(ctx context.Context, tcpNode host.Host, peers []p2p.Peer) (context.Context, context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(ctx)

	type tuple struct {
		Peer peer.ID
		RTT  time.Duration
	}

	var (
		tuples = make(chan tuple, len(peers))
		total  int
	)
	for _, p := range peers {
		if tcpNode.ID() == p.ID {
			continue // Do not connect to self.
		}
		total++
		go func(pID peer.ID) {
			for {
				results, rtt, ok := waitConnect(ctx, tcpNode, pID)
				if ctx.Err() != nil {
					return
				} else if !ok {
					continue
				}

				// We are connected
				tuples <- tuple{Peer: pID, RTT: rtt}

				// Wait for disconnect and cancel the context.
				for result := range results {
					if result.Error != nil {
						log.Error(ctx, "Peer connection lost", result.Error, z.Str("peer", p2p.PeerName(pID)))
						cancel()
					}
				}
			}
		}(p.ID)
	}

	var i int
	for {
		select {
		case <-ctx.Done():
			return ctx, cancel, ctx.Err()
		case tuple := <-tuples:
			i++
			log.Info(ctx, fmt.Sprintf("Connected to peer %d of %d", i, total),
				z.Str("peer", p2p.PeerName(tuple.Peer)),
				z.Str("rtt", tuple.RTT.String()),
			)
			if i == total {
				return ctx, cancel, nil
			}
		}
	}
}

// waitConnect blocks until a libp2p connection (ping) is established returning the ping result chan, with the peer or the context is cancelled.
func waitConnect(ctx context.Context, tcpNode host.Host, p peer.ID) (<-chan ping.Result, time.Duration, bool) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	resp := ping.Ping(ctx, tcpNode, p)
	for result := range resp {
		if result.Error == nil {
			return resp, result.RTT, true
		} else if ctx.Err() != nil {
			return nil, 0, false
		}

		log.Warn(ctx, "Failed connecting to peer (will retry)", result.Error, z.Str("peer", p2p.PeerName(p)))
		time.Sleep(time.Second * 5) // TODO(corver): Improve backoff.
	}

	return nil, 0, false
}

func forkVersionToNetwork(forkVersion string) (string, error) {
	switch forkVersion {
	case "0x00001020":
		return "prater", nil
	case "0x60000069":
		return "kintsugi", nil
	case "0x70000069":
		return "kiln", nil
	case "0x00000064":
		return "gnosis", nil
	case "0x00000000":
		return "mainnet", nil
	default:
		return "", errors.New("invalid fork version")
	}
}
