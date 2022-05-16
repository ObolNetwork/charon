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
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/parsigdb"
	"github.com/obolnetwork/charon/core/parsigex"
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

// exchanger is responsible for exchanging partial signatures between peers on libp2p.
type exchanger struct {
	setChan chan core.ParSignedDataSet
	sigex   *parsigex.ParSigEx
}

func newExchanger(tcpNode host.Host, peerIdx int, peers []peer.ID) exchanger {
	ex := exchanger{
		sigex:   parsigex.NewParSigEx(tcpNode, peerIdx, peers),
		setChan: make(chan core.ParSignedDataSet, len(peers)),
	}

	// Wiring core workflow components
	ex.sigex.Subscribe(ex.getSets)

	return ex
}

func (e *exchanger) exchange(ctx context.Context, set core.ParSignedDataSet) ([]core.ParSignedDataSet, error) {
	err := e.sigex.Broadcast(ctx, core.Duty{}, set)
	if err != nil {
		return nil, err
	}

	var sets []core.ParSignedDataSet
	sets = append(sets, set)
	for {
		select {
		case <-ctx.Done():
			return nil, err
		case peerSet := <-e.setChan:
			sets = append(sets, peerSet)
		}

		// We are done when we have ParSignedDataSet from all the peers including the current one
		if len(sets) == cap(e.setChan) {
			break
		}
	}

	return sets, nil
}

func (e *exchanger) getSets(_ context.Context, _ core.Duty, set core.ParSignedDataSet) error {
	e.setChan <- set

	return nil
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

	_ = newExchanger(tcpNode, nodeIdx.PeerIdx, nil)

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

	lock := cluster.Lock{
		Definition: def,
		Validators: dvs,
	}

	if conf.TestSigning {
		sig, err := aggSignLockHash(ctx, tcpNode, nodeIdx, nil, lock, shares)
		if err != nil {
			return err
		}

		lock.SignatureAggregate, err = sig.MarshalBinary()
		if err != nil {
			return errors.Wrap(err, "marshal signature")
		}
	}

	return writeLock(conf.DataDir, lock)
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

// aggSignLockHash returns the aggregated multi signature of the lock hash
// signed by all the distributed validator group private keys.
func aggSignLockHash(ctx context.Context, tcpNode host.Host, nodeIdx cluster.NodeIdx,
	peers []peer.ID, lock cluster.Lock, shares []share,
) (*bls_sig.MultiSignature, error) {
	// Create partial signatures of lock hash
	signedSet, err := signLockHash(lock, nodeIdx.ShareIdx, shares)
	if err != nil {
		return nil, err
	}

	// Wire core workflow components:
	//  - parsigdb: stores our and other's partial signatures.
	//  - parsigex: exchanges signatures between all nodes' parsigdb
	//  - makeSigAgg: aggregates threshold signatures once enough has been received.
	//
	// Note that these components do not contain goroutines (so nothing is started or stopped)
	// These components are driven by the call to sigdb.StoreInternal below and
	// by libp2p messages received from other peers.
	sigChan := make(chan *bls_sig.Signature, len(lock.Validators))    // Make output of sig aggregation
	sigdb := parsigdb.NewMemDB(lock.Threshold)                        // Make parsigdb
	exchange := parsigex.NewParSigEx(tcpNode, nodeIdx.PeerIdx, peers) // Make parsigex
	sigdb.SubscribeInternal(exchange.Broadcast)                       // Wire parsigex to parsigdb
	sigdb.SubscribeThreshold(makeSigAgg(sigChan))                     // Wire sigagg to parsigdb output
	exchange.Subscribe(sigdb.StoreExternal)                           // Wire parsigdb to parsigex

	// Start the process by inserting the partial signatures
	err = sigdb.StoreInternal(ctx, core.Duty{}, signedSet)
	if err != nil {
		return nil, err
	}

	// Wait until all group signatures pop out.
	var sigs []*bls_sig.Signature
	for {
		select {
		case <-ctx.Done():
			return nil, err
		case sig := <-sigChan:
			sigs = append(sigs, sig)
		}
		if len(sigs) == len(lock.Validators) {
			break
		}
	}

	// Aggregate all group signatures.
	b, err := tbls.Scheme().AggregateSignatures(sigs...)
	if err != nil {
		return nil, errors.Wrap(err, "aggregate signature")
	}

	return b, nil
}

// makeSigAgg returns a function that aggregates partial signatures.
func makeSigAgg(sigChan chan<- *bls_sig.Signature) func(context.Context, core.Duty, core.PubKey, []core.ParSignedData) error {
	return func(ctx context.Context, duty core.Duty, key core.PubKey, parSigs []core.ParSignedData) error {
		var sigs []*bls_sig.PartialSignature
		for _, parSig := range parSigs {
			s, err := tblsconv.SigFromCore(parSig.Signature)
			if err != nil {
				return errors.Wrap(err, "convert signature")
			}

			sigs = append(sigs, &bls_sig.PartialSignature{
				Identifier: byte(parSig.ShareIdx),
				Signature:  s.Value,
			})
		}

		agg, err := tbls.Aggregate(sigs)
		if err != nil {
			return err
		}

		sigChan <- agg

		return nil
	}
}

// signLockHash returns a partially signed dataset containing signatures of the lock hash be each DV.
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
			Data:      nil,
			Signature: sigBytes,
			ShareIdx:  shareIdx,
		}
	}

	return set, nil
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
