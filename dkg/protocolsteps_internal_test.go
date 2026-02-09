// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/bcast"
	"github.com/obolnetwork/charon/dkg/pedersen"
	"github.com/obolnetwork/charon/dkg/share"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
)

func TestNoopProtocolStep(t *testing.T) {
	step := &noopProtocolStep{}

	err := step.Run(t.Context(), nil)

	require.NoError(t, err)
}

func TestReshareProtocolStep(t *testing.T) {
	const (
		threshold = 3
		numNodes  = 4
		numVals   = 2
	)

	oldShares := make([][]share.Share, numNodes)
	oldSecrets := [][]string{
		{
			"698bf874afad4b65057c63e4b75485dd4c08af60b7d32fd7aa5e70bfce619c35",
			"057a6d79a11cb6006dca3f4bdb05c5f4fffa828034d3049eeda012cd5678dd3a",
		},
		{
			"6de2b6df0b0cae8a79dd58bafe3f4e33dfb386bbabf84cf82d5a17f8d93659d0",
			"37a01478c20b44eeceb26e20bb6a99984121455e2781945ccbc1f312a988c50c",
		},
		{
			"1d1ca6859f85b74188be77774318203799cbbd53db4969862f66385791632159",
			"110bbe177f9595b7c8a432449b135fffe84be54941ea4efa14f16dd4cc53368e",
		},
		{
			"5f15160ec053601a989370299922abf321cc9b2f45c33d7fb082d1d9f6e7f2d2",
			"05ab11a9035925a38ed963bf83a1f13149380644840b9075c92e8312bed831c1",
		},
	}
	oldPubKeys := []string{
		"b1ff2b0be51638bf0a3f1d7cbebd09b53a19784a452fb006ba1c0984c19dfa64429102c65250866aab70a841fcf84725",
		"9530295879619a9d8cb25276c412f9443e98e4b117643579853a7c126cf98bcf263ccbd39f78786130e41d5b46ab29a1",
	}

	for n := range numNodes {
		oldShares[n] = make([]share.Share, numVals)
		for v := range numVals {
			oldShares[n][v] = share.Share{
				SecretShare: tbls.PrivateKey(pedersen.MustDecodeHex(t, oldSecrets[n][v])),
				PubKey:      tbls.PublicKey(pedersen.MustDecodeHex(t, oldPubKeys[v])),
			}
		}
	}

	var (
		peers   []peer.ID
		peerMap = make(map[peer.ID]cluster.NodeIdx)
		nodes   = make([]*pedersen.TestNode, numNodes)
	)

	for i := range numNodes {
		nodes[i] = pedersen.NewTestNode(t, i)
		peerMap[nodes[i].NodeHost.ID()] = nodes[i].NodeIdx
		peers = append(peers, nodes[i].NodeHost.ID())
	}

	pedersen.ConnectTestNodes(t, nodes)

	session := testutil.RandomArray32()

	for i := range nodes {
		nodes[i].InitBoard(t, threshold, peers, peerMap, session[:])
	}

	group, gctx := errgroup.WithContext(t.Context())

	// Create a cluster lock with the expected validator public keys
	lock := &cluster.Lock{
		Validators: make([]cluster.DistValidator, numVals),
	}
	for i, pubKey := range oldPubKeys {
		lock.Validators[i] = cluster.DistValidator{
			PubKey: pedersen.MustDecodeHex(t, pubKey),
		}
	}

	for n := range nodes {
		group.Go(func() error {
			nodes[n].Config.Reshare = &pedersen.ReshareConfig{TotalShares: numVals, NewThreshold: threshold}

			step := &reshareProtocolStep{
				config: nodes[n].Config,
				board:  nodes[n].Board,
			}
			pctx := &ProtocolContext{
				Shares: oldShares[n],
				Lock:   lock,
			}

			return step.Run(gctx, pctx)
		})
	}

	err := group.Wait()
	require.NoError(t, err, "Reshare failed on one or more nodes")
}

func TestUpdateLockProtocolStep(t *testing.T) {
	step := &updateLockProtocolStep{
		threshold: 4,
		operators: []string{"foo", "bar"},
	}

	random := rand.New(rand.NewSource(0))
	lock, nodeKeys, valKeys := cluster.NewForT(t, 3, 3, 4, 0, random)

	shares := valKeysToSharesNode0(t, valKeys, lock.Validators)

	host := testutil.CreateHost(t, testutil.AvailableAddr(t))
	sigex := newExchanger(host, 0, []peer.ID{host.ID()}, []sigType{sigLock}, 10*time.Second)

	pctx := &ProtocolContext{
		Lock:          &lock,
		ENRPrivateKey: nodeKeys[0],
		Shares:        shares,
		SigExchanger:  sigex,
		ThisNodeIdx:   cluster.NodeIdx{PeerIdx: 0, ShareIdx: 1},
	}
	err := step.Run(t.Context(), pctx)

	require.NoError(t, err)
	require.Equal(t, 4, pctx.Lock.Threshold)
	require.Len(t, pctx.Lock.Operators, 2)
	require.Equal(t, "foo", pctx.Lock.Operators[0].ENR)
	require.Equal(t, "bar", pctx.Lock.Operators[1].ENR)
	require.NotEqual(t, lock.LockHash, pctx.Lock.LockHash)
	require.NotEqual(t, lock.SignatureAggregate, pctx.Lock.SignatureAggregate)
}

func TestUpdateNodeSignaturesProtocolStep(t *testing.T) {
	const (
		threshold = 3
		numNodes  = 4
		numVals   = 2
	)

	random := rand.New(rand.NewSource(0))
	lock, nodeKeys, _ := cluster.NewForT(t, numVals, threshold, numNodes, 0, random)

	var (
		peers   []peer.ID
		peerMap = make(map[peer.ID]cluster.NodeIdx)
		nodes   = make([]*pedersen.TestNode, numNodes)
	)

	for i := range numNodes {
		nodes[i] = pedersen.NewTestNodeWithKey(t, i, nodeKeys[i])
		peerMap[nodes[i].NodeHost.ID()] = nodes[i].NodeIdx
		peers = append(peers, nodes[i].NodeHost.ID())
	}

	pedersen.ConnectTestNodes(t, nodes)

	allPeers, err := lock.Peers()
	require.NoError(t, err)

	group, gctx := errgroup.WithContext(t.Context())

	for n := range numNodes {
		group.Go(func() error {
			caster := bcast.New(nodes[n].NodeHost, peers, nodeKeys[n])
			nodeSigCaster := newNodeSigBcast(allPeers, cluster.NodeIdx{PeerIdx: n, ShareIdx: n + 1}, caster)

			step := &updateNodeSignaturesProtocolStep{}
			lockCopy := lock
			pctx := &ProtocolContext{
				Lock:          &lockCopy,
				ENRPrivateKey: nodeKeys[n],
				ThisNodeIdx:   cluster.NodeIdx{PeerIdx: n, ShareIdx: n + 1},
				NodeSigCaster: nodeSigCaster,
			}

			return step.Run(gctx, pctx)
		})
	}

	err = group.Wait()
	require.NoError(t, err)
}

func TestWriteArtifactsProtocolStep(t *testing.T) {
	dataDir := t.TempDir()

	step := &writeArtifactsProtocolStep{
		outputDir: t.TempDir(),
	}

	random := rand.New(rand.NewSource(0))
	lock, nodeKeys, valKeys := cluster.NewForT(t, 3, 3, 4, 0, random)

	err := k1util.Save(nodeKeys[0], p2p.KeyPath(dataDir))
	require.NoError(t, err)

	err = os.WriteFile(p2p.KeyPath(dataDir)+".lock", []byte("{}"), 0o600)
	require.NoError(t, err)

	shares := valKeysToSharesNode0(t, valKeys, lock.Validators)

	var receivedLock cluster.Lock

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/lock", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		err = json.Unmarshal(body, &receivedLock)
		require.NoError(t, err)

		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	pctx := &ProtocolContext{
		Lock:           &lock,
		PrivateKeyPath: p2p.KeyPath(dataDir),
		ENRPrivateKey:  nodeKeys[0],
		Shares:         shares,
		ThisNodeIdx:    cluster.NodeIdx{PeerIdx: 0, ShareIdx: 1},
		Config: Config{
			PublishAddr:    mockServer.URL,
			PublishTimeout: 30 * time.Second,
			Publish:        true,
		},
	}
	err = step.Run(t.Context(), pctx)

	require.NoError(t, err)
	require.FileExists(t, filepath.Join(step.outputDir, clusterLockFile))
	require.DirExists(t, filepath.Join(step.outputDir, validatorKeysSubDir))
	require.FileExists(t, p2p.KeyPath(step.outputDir))
	require.FileExists(t, p2p.KeyPath(step.outputDir)+".lock")

	require.NotZero(t, receivedLock.LockHash, "Expected lock to be published to mock server")
	require.Equal(t, lock.LockHash, receivedLock.LockHash)

	enrPrivKey, err := os.ReadFile(p2p.KeyPath(step.outputDir))
	require.NoError(t, err)
	enrPrivKeyBytes, err := hex.DecodeString(string(enrPrivKey))
	require.NoError(t, err)
	require.Equal(t, nodeKeys[0].Serialize(), enrPrivKeyBytes)

	entries, err := os.ReadDir(filepath.Join(step.outputDir, validatorKeysSubDir))
	require.NoError(t, err)
	require.Len(t, entries, 6) // two files per validator

	lockFilePath := filepath.Join(step.outputDir, clusterLockFile)
	l, err := LoadAndVerifyClusterLock(t.Context(), lockFilePath, "", false)
	require.NoError(t, err)
	require.Equal(t, lock, *l)
}

func valKeysToSharesNode0(t *testing.T, valKeys [][]tbls.PrivateKey, vals []cluster.DistValidator) []share.Share {
	t.Helper()

	var shares []share.Share

	for vi, sh := range valKeys {
		pubKey, err := vals[vi].PublicKey()
		require.NoError(t, err)

		ss := share.Share{
			SecretShare:  sh[0],
			PubKey:       pubKey,
			PublicShares: make(map[int]tbls.PublicKey, len(sh)),
		}

		for idx, privKeyShare := range sh {
			pubKeyShare, err := tbls.SecretToPublicKey(privKeyShare)
			require.NoError(t, err)

			ss.PublicShares[idx+1] = pubKeyShare
		}

		shares = append(shares, ss)
	}

	return shares
}
