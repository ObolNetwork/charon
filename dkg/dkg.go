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
	"os"
	"path"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/sharing"
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
	Network string

	TestDef     *cluster.Definition
	TestSigning bool
}

// Run executes a dkg ceremony and writes secret share keystore and cluster lock files as output.
func Run(ctx context.Context, conf Config) error {
	ctx = log.WithTopic(ctx, "dkg")

	if err := log.InitLogger(conf.Log); err != nil {
		return err
	}

	def, err := loadDefinition(conf)
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

	peerIds := make([]peer.ID, 0, len(peers))

	for _, p := range peers {
		peerIds = append(peerIds, p.ID)
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

		err := waitPeers(ctx, tcpNode, peers)
		if err != nil {
			return err
		}

		log.Info(ctx, "Starting Frost DKG ceremony")

		shares, err = runFrostParallel(ctx, tp, uint32(def.NumValidators), uint32(len(peerMap)),
			uint32(def.Threshold), uint32(nodeIdx.ShareIdx), clusterID)
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported dkg algorithm")
	}

	log.Info(ctx, "Successfully completed DKG ceremony, writing output")

	if err := writeKeystores(conf.DataDir, shares); err != nil {
		return err
	}

	dvs, err := dvsFromShares(shares)
	if err != nil {
		return err
	}

	pubkeyToVerifiers := make(map[core.PubKey]*sharing.FeldmanVerifier)
	pubkeyToPubshares := make(map[core.PubKey]map[uint32]*bls_sig.PublicKey)
	for _, sh := range shares {
		pk, err := tblsconv.KeyToCore(sh.PubKey)
		if err != nil {
			return err
		}
		pubkeyToVerifiers[pk] = sh.Verifier
		pubkeyToPubshares[pk] = sh.PublicShares
	}

	// Signing, Aggregating and Writing Lock File
	lock := cluster.Lock{
		Definition: def,
		Validators: dvs,
	}

	sigLockHash, err := signLockHash(lock, nodeIdx.ShareIdx, shares)
	if err != nil {
		return err
	}

	peerSigs, err := ex.exchange(ctx, dutyLock, sigLockHash)
	if err != nil {
		return err
	}

	aggSigLockHash, aggPkLockHash, err := aggLockHashSig(peerSigs, pubkeyToVerifiers, pubkeyToPubshares, def.DKGAlgorithm)
	if err != nil {
		return err
	}

	msg, err := lock.HashTreeRoot()
	if err != nil {
		return err
	}

	verified, err := tbls.Scheme().VerifyMultiSignature(aggPkLockHash, msg[:], aggSigLockHash)
	if err != nil {
		return errors.Wrap(err, "verify multisignature")
	}

	if !verified {
		return errors.New("invalid lock hash aggregated signature")
	}

	sigBytes, err := aggSigLockHash.MarshalBinary()
	if err != nil {
		return errors.Wrap(err, "marshal binary aggSigLockHash")
	}
	lock.SignatureAggregate = sigBytes

	if err = writeLock(conf.DataDir, lock); err != nil {
		return err
	}

	// Signing, Aggregating and Writing Deposit Data
	sigDepositData, msgs, err := signDepositData(shares, nodeIdx.ShareIdx, def.WithdrawalAddress, conf.Network)
	if err != nil {
		return err
	}

	peerSigs, err = ex.exchange(ctx, dutyDepositData, sigDepositData)
	if err != nil {
		return err
	}

	aggSigDepositData, err := aggDepositDataSigs(peerSigs)
	if err != nil {
		return err
	}

	for pk, sig := range aggSigDepositData {
		pubkey, err := tblsconv.KeyFromCore(pk)
		if err != nil {
			return err
		}
		ok, err := tbls.Verify(pubkey, msgs[pk], sig)
		if err != nil {
			return err
		}

		if !ok {
			return errors.New("invalid deposit data aggregated signature")
		}
	}

	return writeDepositData(aggSigDepositData, def.WithdrawalAddress, conf.Network, conf.DataDir)
}

func writeDepositData(aggSigs map[core.PubKey]*bls_sig.Signature, withdrawalAddr string, network string, dataDir string) error {
	// Create deposit message signatures
	aggSigsEth2 := make(map[eth2p0.BLSPubKey]eth2p0.BLSSignature)
	for pk, sig := range aggSigs {
		blsPubKey, err := tblsconv.KeyFromCore(pk)
		if err != nil {
			return nil
		}

		pubkey, err := tblsconv.KeyToETH2(blsPubKey)
		if err != nil {
			return err
		}

		sigEth2 := tblsconv.SigToETH2(sig)
		aggSigsEth2[pubkey] = sigEth2
	}

	// Serialize the deposit data into bytes
	bytes, err := deposit.MarshalDepositData(aggSigsEth2, withdrawalAddr, network)
	if err != nil {
		return err
	}

	// Write it to disk
	depositPath := path.Join(dataDir, "deposit-data.json")
	err = os.WriteFile(depositPath, bytes, 0o400) // read-only
	if err != nil {
		return errors.Wrap(err, "write deposit data")
	}

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

	tcpNode, err := p2p.NewTCPNode(p2pConf, key, p2p.NewOpenGater(), udpNode, peers, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "")
	}

	// Register ping service handler
	_ = ping.NewPingService(tcpNode)

	return tcpNode, func() {
		db.Close()
		udpNode.Close()
		_ = tcpNode.Close()
	}, nil
}

// aggLockHashSig returns the aggregated multi signature of the lock hash
// signed by all the distributed validator group private keys.
func aggLockHashSig(data map[core.PubKey][]core.ParSignedData, verifiers map[core.PubKey]*sharing.FeldmanVerifier, pubshares map[core.PubKey]map[uint32]*bls_sig.PublicKey, dkgAlgo string) (*bls_sig.MultiSignature, *bls_sig.MultiPublicKey, error) {
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
				pubshare, err = tbls.GetPubShare(s.ShareIdx, verifiers[pk])
				if err != nil {
					return nil, nil, errors.Wrap(err, "get pubshare from verifier")
				}
			case "frost":
				pubshare = pubshares[pk][uint32(s.ShareIdx)]
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

// aggDepositDataSigs returns the threshold aggregated signatures of the deposit data per DV
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
			Verifiers: msg.Verifiers,
			PubShares: msg.PubShares,
		})
	}

	return dvs, nil
}

// waitPeers blocks until all peers are connected or the context is cancelled.
func waitPeers(ctx context.Context, tcpNode host.Host, peers []p2p.Peer) error {
	// TODO(corver): This can be improved by returning a context that is
	//  cancelled as soon as the connection to a single peer is lost.

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
			rtt := waitConnect(ctx, tcpNode, pID)
			if ctx.Err() == nil {
				tuples <- tuple{Peer: pID, RTT: rtt}
			}
		}(p.ID)
	}

	var i int
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case tuple := <-tuples:
			i++
			log.Info(ctx, fmt.Sprintf("Connected to peer %d of %d", i, total),
				z.Str("peer", p2p.ShortID(tuple.Peer)),
				z.Str("rtt", tuple.RTT.String()),
			)
			if i == total {
				return nil
			}
		}
	}
}

// waitConnect blocks until a libp2p connection (ping) is established with the peer or the context is cancelled.
func waitConnect(ctx context.Context, tcpNode host.Host, p peer.ID) time.Duration {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for result := range ping.Ping(ctx, tcpNode, p) {
		if result.Error == nil {
			return result.RTT
		} else if ctx.Err() != nil {
			return 0
		}

		log.Warn(ctx, "Failed connecting to peer (will retry)", result.Error, z.Str("peer", p2p.ShortID(p)))
		time.Sleep(time.Second * 5) // TODO(corver): Improve backoff.
	}

	return 0
}
