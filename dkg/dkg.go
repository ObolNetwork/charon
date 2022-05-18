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

// Values of following constants should not change as it can break backwards compatibility.
const (
	// dutyLock is responsible for lock hash signed partial signatures exchange and aggregation.
	dutyLock core.DutyType = 101
	// dutyDepositData is responsible for deposit data signed partial signatures exchange and aggregation.
	dutyDepositData core.DutyType = 102
)

type Config struct {
	DefFile string
	DataDir string
	P2P     p2p.Config
	Log     log.Config

	TestDef     *cluster.Definition
	TestSigning bool
}

// sigData includes the fields obtained from sigdb when threshold is reached.
type sigData struct {
	duty   core.DutyType
	pubkey core.PubKey
	psigs  []core.ParSignedData
}

// exchanger is responsible for exchanging partial signatures between peers on libp2p.
type exchanger struct {
	sigChan chan sigData
	sigex   *parsigex.ParSigEx
	sigdb   *parsigdb.MemDB
	numVals int
}

func newExchanger(tcpNode host.Host, peerIdx int, peers []peer.ID, vals int) *exchanger {
	ex := &exchanger{
		// threshold is len(peers) to wait until we get all the partial sigs from all the peers per DV
		sigdb:   parsigdb.NewMemDB(len(peers)),
		sigex:   parsigex.NewParSigEx(tcpNode, peerIdx, peers),
		sigChan: make(chan sigData),
		numVals: vals,
	}

	// Wiring core workflow components
	ex.sigdb.SubscribeInternal(ex.sigex.Broadcast)
	ex.sigdb.SubscribeThreshold(ex.pushPsigs)
	ex.sigex.Subscribe(ex.sigdb.StoreExternal)

	return ex
}

// exchange exhanges partial signatures of lockhash/deposit-data among dkg participants and returns all the partial
// signatures of the group according to public key of each DV.
func (e *exchanger) exchange(ctx context.Context, duty core.DutyType, set core.ParSignedDataSet) (map[core.PubKey][]core.ParSignedData, error) {
	// Start the process by storing current peer's ParSignedDataSet
	err := e.sigdb.StoreInternal(ctx, core.Duty{Type: duty}, set)
	if err != nil {
		return nil, err
	}

	sets := make(map[core.PubKey][]core.ParSignedData)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case peerSet := <-e.sigChan:
			if duty != peerSet.duty {
				// Do nothing if duty doesn't match
				continue
			}

			switch peerSet.duty {
			case dutyLock, dutyDepositData:
				sets[peerSet.pubkey] = peerSet.psigs
			default:
				return nil, errors.New("invalid data")
			}
		}

		// We are done when we have ParSignedData of all the DVs from all each peer
		if len(sets) == e.numVals {
			break
		}
	}

	return sets, nil
}

// pushPsigs is responsible for writing partial signature data to sigChan obtained from other peers.
func (e *exchanger) pushPsigs(_ context.Context, duty core.Duty, pk core.PubKey, psigs []core.ParSignedData) error {
	e.sigChan <- sigData{
		duty:   duty.Type,
		pubkey: pk,
		psigs:  psigs,
	}

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

	_ = newExchanger(tcpNode, nodeIdx.PeerIdx, nil, def.NumValidators)

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

	// if conf.TestSigning {
	//	sig, err := aggSignLockHash(ctx, tcpNode, nodeIdx, nil, lock, shares)
	//	if err != nil {
	//		return err
	//	}
	//
	//	lock.SignatureAggregate, err = sig.MarshalBinary()
	//	if err != nil {
	//		return errors.Wrap(err, "marshal signature")
	//	}
	//}

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

// aggLockHashSigs returns the aggregated multi signature of the lock hash
// signed by all the distributed validator group private keys.
//nolint: deadcode
func aggLockHashSigs(data map[core.PubKey][]core.ParSignedData) (*bls_sig.MultiSignature, *bls_sig.MultiPublicKey, error) {
	var (
		sigs    []*bls_sig.Signature
		pubkeys []*bls_sig.PublicKey
	)
	for pk, psigs := range data {
		pubkey, err := tblsconv.KeyFromCore(pk)
		if err != nil {
			return nil, nil, err
		}
		pubkeys = append(pubkeys, pubkey)

		for _, s := range psigs {
			sig := &bls_sig.Signature{}
			err = sig.UnmarshalBinary(s.Signature)
			if err != nil {
				return nil, nil, errors.Wrap(err, "Unmarshal signature")
			}

			sigs = append(sigs, sig)
		}
	}

	// Full BLS Signature Aggregation
	aggSig, err := tbls.Scheme().AggregateSignatures(sigs...)
	if err != nil {
		return nil, nil, errors.Wrap(err, "BLS Aggregate Signatures")
	}

	// Aggregate Public Keys to verify aggregated signature
	aggPubKey, err := tbls.Scheme().AggregatePublicKeys(pubkeys...)
	if err != nil {
		return nil, nil, errors.Wrap(err, "BLS Aggregate Public Keys")
	}

	return aggSig, aggPubKey, nil
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
