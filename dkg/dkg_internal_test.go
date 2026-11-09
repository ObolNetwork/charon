// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/peerinfo"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/dkg/share"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
)

func TestInvalidSignatures(t *testing.T) {
	const (
		n  = 4
		th = 3
	)

	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	secretShares, err := tbls.ThresholdSplit(secret, n, th)
	require.NoError(t, err)

	pubshares := make(map[int]tbls.PublicKey)

	for idx, share := range secretShares {
		pubkey, err := tbls.SecretToPublicKey(share)
		require.NoError(t, err)

		pubshares[idx] = pubkey
	}

	shares := share.Share{
		PubKey:       pubkey,
		SecretShare:  secretShares[0],
		PublicShares: pubshares,
	}

	getSigs := func(msg []byte) []core.ParSignedData {
		var sigs []core.ParSignedData

		for i := range n - 1 {
			sig, err := tbls.Sign(secretShares[i+1], msg)
			require.NoError(t, err)

			sigs = append(sigs, core.NewPartialSignature(tblsconv.SigToCore(sig), i+1))
		}

		invalidSig, err := tbls.Sign(secretShares[n-1], []byte("invalid msg"))
		require.NoError(t, err)

		sigs = append(sigs, core.NewPartialSignature(tblsconv.SigToCore(invalidSig), n))

		return sigs
	}

	corePubkey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)

	// Aggregate and verify deposit data signatures
	msg := testutil.RandomDepositMsg(t)

	_, err = aggDepositData(
		map[core.PubKey][]core.ParSignedData{corePubkey: getSigs([]byte("any digest"))},
		[]share.Share{shares},
		map[core.PubKey]eth2p0.DepositMessage{corePubkey: msg},
		eth2util.Goerli.Name,
	)
	require.EqualError(t, err, "invalid deposit data partial signature from peer")

	// Aggregate and verify cluster lock hash signatures
	lockMsg := []byte("cluster lock hash")

	_, _, err = aggLockHashSig(map[core.PubKey][]core.ParSignedData{corePubkey: getSigs(lockMsg)}, map[core.PubKey]share.Share{corePubkey: shares}, lockMsg)
	require.EqualError(t, err, "invalid lock hash partial signature from peer: signature not verified")
}

func TestValidSignatures(t *testing.T) {
	const (
		n  = 4
		th = 3
	)

	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	secretShares, err := tbls.ThresholdSplit(secret, n, th)
	require.NoError(t, err)

	pubshares := make(map[int]tbls.PublicKey)

	for idx, share := range secretShares {
		pubkey, err := tbls.SecretToPublicKey(share)
		require.NoError(t, err)

		pubshares[idx] = pubkey
	}

	shares := share.Share{
		PubKey:       pubkey,
		SecretShare:  secret,
		PublicShares: pubshares,
	}

	getSigs := func(msg []byte) []core.ParSignedData {
		var sigs []core.ParSignedData

		for i := range n - 1 {
			pk := secretShares[i+1]
			sig, err := tbls.Sign(pk, msg)
			require.NoError(t, err)

			coreSig := tblsconv.SigToCore(sig)
			sigs = append(sigs, core.NewPartialSignature(coreSig, i+1))
		}

		return sigs
	}

	corePubkey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	eth2Pubkey, err := corePubkey.ToETH2()
	require.NoError(t, err)

	withdrawalAddr := testutil.RandomETHAddress()
	network := eth2util.Goerli.Name

	msg, err := deposit.NewMessage(eth2Pubkey, withdrawalAddr, deposit.DefaultDepositAmount, true)
	require.NoError(t, err)
	sigRoot, err := deposit.GetMessageSigningRoot(msg, network)
	require.NoError(t, err)

	_, err = aggDepositData(
		map[core.PubKey][]core.ParSignedData{corePubkey: getSigs(sigRoot[:])},
		[]share.Share{shares},
		map[core.PubKey]eth2p0.DepositMessage{corePubkey: msg},
		network,
	)
	require.NoError(t, err)

	// Aggregate and verify cluster lock hash signatures
	lockMsg := []byte("cluster lock hash")

	_, _, err = aggLockHashSig(map[core.PubKey][]core.ParSignedData{corePubkey: getSigs(lockMsg)}, map[core.PubKey]share.Share{corePubkey: shares}, lockMsg)
	require.NoError(t, err)
}

func TestValidateKeymanagerFlags(t *testing.T) {
	tests := []struct {
		name      string
		addr      string
		authToken string
		errMsg    string
	}{
		{
			name:      "Both keymanager flags provided",
			addr:      "https://keymanager@example.com",
			authToken: "keymanager-auth-token",
			errMsg:    "",
		},
		{
			name:   "Address provided but auth token absent",
			addr:   "https://keymanager@example.com",
			errMsg: "--keymanager-address provided but --keymanager-auth-token not set, fix configuration flags",
		},
		{
			name:      "Auth token provided by address absent",
			authToken: "keymanager-auth-token",
			errMsg:    "--keymanager-auth-token provided but --keymanager-address not set, fix configuration flags",
		},
		{
			name:      "Malformed address provided",
			addr:      "https://keymanager@example.com:-80",
			authToken: "keymanager-auth-token",
			errMsg:    "parse keymanager address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKeymanagerFlags(context.Background(), tt.addr, tt.authToken)
			if tt.errMsg != "" {
				require.ErrorContains(t, err, tt.errMsg)
			}
		})
	}
}

func TestCheckThreshold(t *testing.T) {
	tests := []struct {
		name         string
		threshold    int
		numOperators int
		errMsg       string
		warnMsg      string
	}{
		{
			name:         "safe threshold",
			threshold:    3,
			numOperators: 4,
		},
		{
			name:         "unsafe low threshold",
			threshold:    2,
			numOperators: 4,
			warnMsg:      "Cluster definition threshold differs from recommended value",
		},
		{
			name:         "unsafe high threshold",
			threshold:    4,
			numOperators: 4,
			warnMsg:      "Cluster definition threshold differs from recommended value",
		},
		{
			name:         "threshold below minimum",
			threshold:    1,
			numOperators: 4,
			errMsg:       "threshold below minimum",
		},
		{
			name:         "threshold exceeds number of operators",
			threshold:    5,
			numOperators: 4,
			errMsg:       "threshold exceeds number of operators",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf zaptest.Buffer

			log.InitLogfmtForT(t, &buf)

			err := checkThreshold(context.Background(), tt.threshold, tt.numOperators)
			if tt.errMsg != "" {
				require.ErrorContains(t, err, tt.errMsg)
				return
			}

			require.NoError(t, err)

			if tt.warnMsg != "" {
				require.Contains(t, buf.String(), tt.warnMsg)
			} else {
				require.Empty(t, buf.String())
			}
		})
	}
}

// TestStartSyncProtocolThreshold verifies the minimum participant mode: three of four nodes
// complete the step and shutdown syncs without the absent fourth, which is rejected when it
// joins late.
func TestStartSyncProtocolThreshold(t *testing.T) {
	const (
		n            = 4
		started      = 3
		minConnected = 2
	)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	keys, hosts, peerIDs := newSyncHosts(t, n)
	connectSyncHosts(hosts, func(int, int) bool { return true })

	defHash := testutil.RandomBytes32()
	testConfig := TestConfig{StragglerWait: 100 * time.Millisecond}

	type result struct {
		idx          int
		step         func(context.Context) error
		shutdown     func(context.Context) error
		fatal        func() error
		participants []peer.ID
		err          error
	}

	var failed atomic.Bool

	results := make(chan result, started)

	// Node 3 is never started, the others proceed once two peers are connected.
	for i := range started {
		go func() {
			step, shutdown, fatal, participants, err := startSyncProtocol(ctx, hosts[i], keys[i], defHash, peerIDs, minConnected,
				func() { failed.Store(true) }, testConfig, "")
			results <- result{idx: i, step: step, shutdown: shutdown, fatal: fatal, participants: participants, err: err}
		}()
	}

	nodes := make([]result, started)

	for range started {
		res := <-results
		require.NoError(t, res.err)

		var others []peer.ID

		for j := range started {
			if j != res.idx {
				others = append(others, peerIDs[j])
			}
		}

		require.ElementsMatch(t, others, res.participants)
		nodes[res.idx] = res
	}

	// The fourth node joining after the freeze fails fast with an explicit error.
	lateCtx, lateCancel := context.WithCancel(ctx)
	defer lateCancel()

	requireSyncError(t, "ceremony already in progress, you were not part of it")(
		startSyncProtocol(lateCtx, hosts[3], keys[3], defHash, peerIDs, minConnected, lateCancel, testConfig, ""))

	errs := make(chan error, started)

	for _, node := range nodes {
		go func() {
			err := node.step(ctx)
			if err != nil {
				errs <- err
				return
			}

			errs <- node.shutdown(ctx)
		}()
	}

	for range started {
		require.NoError(t, <-errs)
	}

	for _, node := range nodes {
		require.NoError(t, node.fatal())
	}

	require.False(t, failed.Load())
	require.NoError(t, ctx.Err())
}

// TestStartSyncProtocolLateJoinerDialedByFrozen verifies a late joiner that cannot dial the frozen nodes
// still gets the explicit error: their clients to absent peers keep running after the freeze and connect to it.
func TestStartSyncProtocolLateJoinerDialedByFrozen(t *testing.T) {
	const (
		n            = 4
		minConnected = 2
	)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	keys, hosts, peerIDs := newSyncHosts(t, n-1)

	// The late joiner's host only starts after the freeze, and knows no addresses: only the others can dial it.
	lateKey, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	latePeerID, err := p2p.PeerIDFromKey(lateKey.PubKey())
	require.NoError(t, err)

	peerIDs = append(peerIDs, latePeerID)

	connectSyncHosts(hosts, func(int, int) bool { return true })

	defHash := testutil.RandomBytes32()
	testConfig := TestConfig{StragglerWait: 100 * time.Millisecond}

	var failed atomic.Bool

	type result struct {
		step     func(context.Context) error
		shutdown func(context.Context) error
		err      error
	}

	results := make(chan result, n-1)

	for i := range n - 1 {
		go func() {
			step, shutdown, _, _, err := startSyncProtocol(ctx, hosts[i], keys[i], defHash, peerIDs, minConnected,
				func() { failed.Store(true) }, testConfig, "")
			results <- result{step: step, shutdown: shutdown, err: err}
		}()
	}

	var nodes []result

	for range n - 1 {
		res := <-results
		require.NoError(t, res.err)

		nodes = append(nodes, res)
	}

	lateHost := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), lateKey)
	for _, h := range hosts {
		h.Peerstore().AddAddrs(latePeerID, lateHost.Addrs(), peerstore.PermanentAddrTTL)
	}

	lateCtx, lateCancel := context.WithTimeout(ctx, 10*time.Second)
	defer lateCancel()

	start := time.Now()

	requireSyncError(t, "ceremony already in progress, you were not part of it")(
		startSyncProtocol(lateCtx, lateHost, lateKey, defHash, peerIDs, minConnected, lateCancel, testConfig, ""))
	require.Less(t, time.Since(start), 8*time.Second)

	errs := make(chan error, n-1)

	for _, node := range nodes {
		go func() {
			err := node.step(ctx)
			if err != nil {
				errs <- err
				return
			}

			errs <- node.shutdown(ctx)
		}()
	}

	for range n - 1 {
		require.NoError(t, <-errs)
	}

	require.False(t, failed.Load())
}

// TestStartSyncProtocolDivergingFreeze verifies that diverging frozen sets fail every node promptly instead
// of hanging: A and C freeze {B,C,D}/{A,B,D}, B (which cannot reach D yet) freezes {A,C}, then D reaches B,
// is rejected and exits, so A and C time out waiting for D, and B times out waiting for A and C.
func TestStartSyncProtocolDivergingFreeze(t *testing.T) {
	const (
		a, b, c, d   = 0, 1, 2, 3
		minConnected = 2
		postFreeze   = 2 * time.Second
	)

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	keys, hosts, peerIDs := newSyncHosts(t, 4)
	isBD := func(i, j int) bool { return (i == b && j == d) || (i == d && j == b) }
	connectSyncHosts(hosts, func(i, j int) bool { return !isBD(i, j) })

	defHash := testutil.RandomBytes32()
	stragglerWaits := map[int]time.Duration{a: 100 * time.Millisecond, b: 200 * time.Millisecond, c: 100 * time.Millisecond, d: 30 * time.Second}

	type result struct {
		idx          int
		step         func(context.Context) error
		participants []peer.ID
		err          error
	}

	results := make(chan result, len(hosts))
	start := time.Now()

	for i := range hosts {
		nodeCtx, nodeCancel := context.WithCancel(ctx)
		defer nodeCancel()

		testConfig := TestConfig{StragglerWait: stragglerWaits[i], PostFreezeTimeout: postFreeze}

		go func() {
			step, _, _, participants, err := startSyncProtocol(nodeCtx, hosts[i], keys[i], defHash, peerIDs, minConnected, nodeCancel, testConfig, "")
			results <- result{idx: i, step: step, participants: participants, err: err}
		}()
	}

	errs := make(map[int]error)

	for range hosts {
		res := <-results
		if res.idx != b {
			errs[res.idx] = res.err
			continue
		}

		require.NoError(t, res.err)
		require.ElementsMatch(t, []peer.ID{peerIDs[a], peerIDs[c]}, res.participants)

		// B is frozen without D: now let D reach B.
		connectSyncHosts(hosts, isBD)

		errs[b] = res.step(ctx)
	}

	require.Less(t, time.Since(start), 20*time.Second)

	require.ErrorContains(t, errs[d], "ceremony already in progress, you were not part of it")

	for _, idx := range []int{a, c} {
		require.ErrorIs(t, errs[idx], context.DeadlineExceeded)
		require.True(t, z.ContainsField(errs[idx], z.Str("missing_peers", p2p.PeerName(peerIDs[d]))), errs[idx])
	}

	require.ErrorIs(t, errs[b], context.DeadlineExceeded)
	require.True(t, z.ContainsField(errs[b], z.Str("missing_peers", peerNames([]peer.ID{peerIDs[a], peerIDs[c]}))), errs[b])
}

// TestStartSyncProtocolJoinTimeout verifies the join timeout lists the absent peers in the minimum participant mode.
func TestStartSyncProtocolJoinTimeout(t *testing.T) {
	const minConnected = 2

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	keys, hosts, peerIDs := newSyncHosts(t, 4)
	connectSyncHosts(hosts, func(int, int) bool { return true })

	defHash := testutil.RandomBytes32()

	// Nodes 2 and 3 never start, so nodes 0 and 1 only see each other.
	errs := make(chan error, 2)

	for i := range 2 {
		go func() {
			_, _, _, _, err := startSyncProtocol(ctx, hosts[i], keys[i], defHash, peerIDs, minConnected, func() {}, TestConfig{}, "")
			errs <- err
		}()
	}

	for range 2 {
		err := <-errs
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.ErrorContains(t, err, "not enough peers connected")
		require.True(t, z.ContainsField(err, z.Int("connected", 1)), err)
		require.True(t, z.ContainsField(err, z.Int("required", minConnected)), err)
		require.True(t, z.ContainsField(err, z.Str("missing_peers", peerNames(peerIDs[2:]))), err)
	}
}

// newSyncHosts returns n in-process libp2p hosts with their keys and peer IDs.
func newSyncHosts(t *testing.T, n int) ([]*k1.PrivateKey, []host.Host, []peer.ID) {
	t.Helper()

	var (
		keys    []*k1.PrivateKey
		hosts   []host.Host
		peerIDs []peer.ID
	)

	for range n {
		key, err := k1.GeneratePrivateKey()
		require.NoError(t, err)

		h := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), key)
		keys = append(keys, key)
		hosts = append(hosts, h)
		peerIDs = append(peerIDs, h.ID())
	}

	return keys, hosts, peerIDs
}

// connectSyncHosts adds the addresses of host j to host i's peerstore for every pair allowed by the filter.
func connectSyncHosts(hosts []host.Host, allow func(i, j int) bool) {
	for i := range hosts {
		for j := range hosts {
			if allow(i, j) {
				hosts[i].Peerstore().AddAddrs(hosts[j].ID(), hosts[j].Addrs(), peerstore.PermanentAddrTTL)
			}
		}
	}
}

// TestStartSyncProtocolMinConnectedInvalid verifies minConnected bounds.
func TestStartSyncProtocolMinConnectedInvalid(t *testing.T) {
	key, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	h := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), key)
	peerIDs := []peer.ID{h.ID()}

	for range 2 {
		other, err := k1.GeneratePrivateKey()
		require.NoError(t, err)

		pID, err := p2p.PeerIDFromKey(other.PubKey())
		require.NoError(t, err)

		peerIDs = append(peerIDs, pID)
	}

	for _, minConnected := range []int{-1, 3} {
		requireSyncError(t, "invalid minimum connected peers")(
			startSyncProtocol(t.Context(), h, key, testutil.RandomBytes32(), peerIDs, minConnected, func() {}, TestConfig{}, ""))
	}
}

// requireSyncError returns a function asserting that startSyncProtocol failed with the given error.
func requireSyncError(t *testing.T, contains string) func(step, shutdown func(context.Context) error, fatal func() error, participants []peer.ID, err error) {
	t.Helper()

	return func(step, shutdown func(context.Context) error, fatal func() error, participants []peer.ID, err error) {
		t.Helper()
		require.ErrorContains(t, err, contains)
		require.Nil(t, step)
		require.Nil(t, shutdown)
		require.Nil(t, fatal)
		require.Empty(t, participants)
	}
}

// TestSetupP2PPeerInfo verifies the peerinfo server of a ceremony host answers, e.g. a relay identifying it.
func TestSetupP2PPeerInfo(t *testing.T) {
	key, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	pID, err := p2p.PeerIDFromKey(key.PubKey())
	require.NoError(t, err)

	client := testutil.CreateHost(t, testutil.AvailableAddr(t))
	defer client.Close()

	peers := []p2p.Peer{{ID: pID, Index: 0}, {ID: client.ID(), Index: 1}}
	conf := Config{P2P: p2p.Config{TCPAddrs: []string{testutil.AvailableAddr(t).String()}}}

	node, shutdown, err := setupP2P(t.Context(), key, conf, peers, testutil.RandomBytes32(), "uuid")
	require.NoError(t, err)

	defer shutdown()

	client.Peerstore().AddAddrs(node.ID(), node.Addrs(), peerstore.PermanentAddrTTL)

	_, _, ok, err := peerinfo.DoOnce(t.Context(), client, node.ID())
	require.NoError(t, err)
	require.True(t, ok)
}
