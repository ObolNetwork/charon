// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/dkg/bcast"
	dkgpb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/eth2util/registration"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
)

const testFeeAddr = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"

// newBcastComponents returns n connected bcast components and their cluster peers.
func newBcastComponents(t *testing.T, n int) ([]*bcast.Component, []p2p.Peer, []*k1.PrivateKey) {
	t.Helper()

	var (
		secrets      []*k1.PrivateKey
		tcpNodes     []host.Host
		peers        []peer.ID
		clusterPeers []p2p.Peer
	)

	for i := range n {
		secret, err := k1.GeneratePrivateKey()
		require.NoError(t, err)

		secrets = append(secrets, secret)

		tcpNode := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), secret)
		tcpNodes = append(tcpNodes, tcpNode)
		peers = append(peers, tcpNode.ID())

		e, err := enr.New(secret)
		require.NoError(t, err)

		epeer, err := p2p.NewPeerFromENR(e, i)
		require.NoError(t, err)

		clusterPeers = append(clusterPeers, epeer)
	}

	for i := range n {
		for j := range n {
			tcpNodes[i].Peerstore().AddAddrs(tcpNodes[j].ID(), tcpNodes[j].Addrs(), peerstore.PermanentAddrTTL)
		}
	}

	comps := make([]*bcast.Component, n)
	for i := range n {
		comps[i] = bcast.New(tcpNodes[i], peers, secrets[i], []byte("session hash"))
	}

	return comps, clusterPeers, secrets
}

// runAgreement runs agree on all nodes with the given local contents (nil adopts).
func runAgreement(t *testing.T, lock cluster.Lock, locals []*proposerconfig.Content) ([]proposerconfig.Content, []error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	comps, peers, _ := newBcastComponents(t, len(locals))

	var (
		results = make([]proposerconfig.Content, len(locals))
		errs    = make([]error, len(locals))
		eg      errgroup.Group
	)

	agreements := make([]*contentAgreement, len(locals))
	for i := range locals {
		agreements[i] = newContentAgreement(peers, cluster.NodeIdx{PeerIdx: i}, comps[i], proposerConfigContentMsgID)
	}

	for i := range locals {
		eg.Go(func() error {
			results[i], errs[i] = agreements[i].agree(ctx, lock, locals[i], "test hint")
			return nil
		})
	}

	require.NoError(t, eg.Wait())

	return results, errs
}

func testContent(t *testing.T, lock cluster.Lock, gasLimit uint64) *proposerconfig.Content {
	t.Helper()

	fees := make([]string, len(lock.Validators))
	for i := range fees {
		fees[i] = testFeeAddr
	}

	c, err := proposerconfig.NewContent(lock, fees, gasLimit, nil)
	require.NoError(t, err)

	return &c
}

func TestNodeSigBcastTwoMessageIDs(t *testing.T) {
	const n = 3

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	comps, peers, secrets := newBcastComponents(t, n)

	var (
		lockHash = bytes.Repeat([]byte{1}, 32)
		confHash = bytes.Repeat([]byte{2}, 32)
		lockRes  = make([][][]byte, n)
		confRes  = make([][][]byte, n)
		eg       errgroup.Group
	)

	for i := range n {
		lockSigs := newNodeSigBcast(peers, cluster.NodeIdx{PeerIdx: i}, comps[i], nodeSigMsgID)
		confSigs := newNodeSigBcast(peers, cluster.NodeIdx{PeerIdx: i}, comps[i], proposerConfigSigMsgID)

		eg.Go(func() error {
			var err error

			lockRes[i], err = lockSigs.exchange(ctx, secrets[i], lockHash)

			return err
		})
		eg.Go(func() error {
			var err error

			confRes[i], err = confSigs.exchange(ctx, secrets[i], confHash)

			return err
		})
	}

	require.NoError(t, eg.Wait())

	// Every node holds all signatures of each exchange, each verifying against its own hash only.
	for i := range n {
		require.Len(t, lockRes[i], n)
		require.Len(t, confRes[i], n)

		for j := range n {
			pubk, err := peers[j].PublicKey()
			require.NoError(t, err)

			ok, err := k1util.Verify65(pubk, lockHash, lockRes[i][j])
			require.NoError(t, err)
			require.True(t, ok)

			ok, err = k1util.Verify65(pubk, confHash, confRes[i][j])
			require.NoError(t, err)
			require.True(t, ok)
		}
	}
}

func TestContentAgreementEqual(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 2, 3, 4, 0, rand.New(rand.NewSource(1)))
	c := testContent(t, lock, proposerconfig.DefaultGasLimit)

	results, errs := runAgreement(t, lock, []*proposerconfig.Content{c, c, c, c})
	for i := range errs {
		require.NoError(t, errs[i])
		require.Equal(t, *c, results[i])
	}
}

func TestContentAgreementAdopt(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 2, 3, 4, 0, rand.New(rand.NewSource(1)))
	c := testContent(t, lock, proposerconfig.DefaultGasLimit)

	results, errs := runAgreement(t, lock, []*proposerconfig.Content{nil, c, c, c})
	for i := range errs {
		require.NoError(t, errs[i])
		require.Equal(t, *c, results[i])
	}
}

func TestContentAgreementAllAdopt(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 1, 3, 4, 0, rand.New(rand.NewSource(1)))

	_, errs := runAgreement(t, lock, []*proposerconfig.Content{nil, nil, nil, nil})
	for _, err := range errs {
		require.ErrorContains(t, err, "no operator has a proposer config")
		require.NotContains(t, err.Error(), "test hint")
	}
}

func TestContentAgreementMismatchDiff(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 2, 3, 4, 0, rand.New(rand.NewSource(1)))
	a := testContent(t, lock, proposerconfig.DefaultGasLimit)
	b := testContent(t, lock, 123)

	_, errs := runAgreement(t, lock, []*proposerconfig.Content{a, a, b, a})
	for _, err := range errs {
		require.ErrorContains(t, err, "peer 2")
		require.ErrorContains(t, err, "default.gas_limit: 200000000 -> 123")
		require.True(t, strings.HasSuffix(err.Error(), "\ntest hint"), err.Error())
		require.NotContains(t, err.Error(), "peer 1")
	}
}

func TestContentAgreementNoValidators(t *testing.T) {
	// Seed contents carry no validators; Diff must still work against a lock without any.
	a := &proposerconfig.Content{DefaultConfig: proposerconfig.Settings{FeeRecipient: testFeeAddr, GasLimit: "1"}}
	b := &proposerconfig.Content{DefaultConfig: proposerconfig.Settings{FeeRecipient: testFeeAddr, GasLimit: "2"}}

	_, errs := runAgreement(t, cluster.Lock{}, []*proposerconfig.Content{a, b, a})
	for _, err := range errs {
		require.ErrorContains(t, err, "default.gas_limit: 1 -> 2")
	}
}

func TestContentAgreementNormalisesAddresses(t *testing.T) {
	a := &proposerconfig.Content{DefaultConfig: proposerconfig.Settings{FeeRecipient: testFeeAddr, GasLimit: "1"}}
	b := &proposerconfig.Content{DefaultConfig: proposerconfig.Settings{FeeRecipient: strings.ToLower(testFeeAddr), GasLimit: "1"}}

	_, errs := runAgreement(t, cluster.Lock{}, []*proposerconfig.Content{a, b, a})
	for _, err := range errs {
		require.NoError(t, err)
	}
}

func TestContentAgreementHostileContent(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 2, 3, 4, 0, rand.New(rand.NewSource(1)))
	a := testContent(t, lock, proposerconfig.DefaultGasLimit)
	// Missing default fields, an entry for a pubkey outside the lock and empty maps.
	b := &proposerconfig.Content{ProposerConfig: map[string]proposerconfig.Settings{"0xABCD": {GasLimit: "5"}}}
	c := &proposerconfig.Content{}

	_, errs := runAgreement(t, lock, []*proposerconfig.Content{a, b, c})
	for _, err := range errs {
		require.ErrorContains(t, err, "peer 1")
		require.ErrorContains(t, err, "peer 2")
	}
}

func TestContentAgreementHashOnlyDiff(t *testing.T) {
	a := &proposerconfig.Content{DefaultConfig: proposerconfig.Settings{FeeRecipient: testFeeAddr, GasLimit: "1"}}
	b := &proposerconfig.Content{
		DefaultConfig:  a.DefaultConfig,
		ProposerConfig: map[string]proposerconfig.Settings{"0xabcd": {GasLimit: "5"}},
	}

	_, errs := runAgreement(t, cluster.Lock{}, []*proposerconfig.Content{a, b, a})
	for _, err := range errs {
		require.ErrorContains(t, err, "contents differ outside the compared fields")
	}
}

func TestContentAgreementDuplicateFirstWins(t *testing.T) {
	comps, peers, _ := newBcastComponents(t, 2)
	ag := newContentAgreement(peers, cluster.NodeIdx{PeerIdx: 0}, comps[0], proposerConfigContentMsgID)

	send := func(gas string) error {
		b, err := json.Marshal(proposerconfig.Content{DefaultConfig: proposerconfig.Settings{GasLimit: gas}})
		require.NoError(t, err)

		return ag.broadcastCallback(context.Background(), peers[1].ID, "", &dkgpb.MsgProposerConfigContent{Content: b, PeerIndex: 1})
	}

	require.NoError(t, send("1"))
	require.NoError(t, send("1"))
	require.ErrorContains(t, send("2"), "conflicting")
	require.Equal(t, "1", ag.received[1].content.DefaultConfig.GasLimit)
}

// signOverride returns the validator's registration with the fee recipient and timestamp, signed by its root key.
func signOverride(t *testing.T, lock cluster.Lock, shares [][]tbls.PrivateKey, valIdx int, fee bellatrix.ExecutionAddress, timestamp time.Time) *eth2api.VersionedSignedValidatorRegistration {
	t.Helper()

	sharesMap := make(map[int]tbls.PrivateKey)
	for i, share := range shares[valIdx] {
		sharesMap[i+1] = share
	}

	root, err := tbls.RecoverSecret(sharesMap, uint(len(shares[valIdx])), uint(lock.Threshold))
	require.NoError(t, err)

	msg := &eth2v1.ValidatorRegistration{
		FeeRecipient: fee,
		GasLimit:     registration.DefaultGasLimit,
		Timestamp:    timestamp,
		Pubkey:       eth2p0.BLSPubKey(lock.Validators[valIdx].PubKey),
	}

	sigRoot, err := registration.GetMessageSigningRoot(msg, eth2p0.Version(lock.ForkVersion))
	require.NoError(t, err)

	sig, err := tbls.Sign(root, sigRoot[:])
	require.NoError(t, err)

	return &eth2api.VersionedSignedValidatorRegistration{
		Version: eth2spec.BuilderVersionV1,
		V1:      &eth2v1.SignedValidatorRegistration{Message: msg, Signature: eth2p0.BLSSignature(sig)},
	}
}

func TestProposerConfigGenesis(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 3, 3, 4, 0, rand.New(rand.NewSource(1)))
	lockFees := lock.FeeRecipientAddresses()

	newer := bellatrix.ExecutionAddress{19: 0x99}
	older := bellatrix.ExecutionAddress{19: 0x98}
	lockTime := lock.Validators[1].BuilderRegistration.Message.Timestamp

	overrides := []*eth2api.VersionedSignedValidatorRegistration{
		signOverride(t, lock, shares, 0, newer, time.Now()),
		signOverride(t, lock, shares, 1, older, lockTime.Add(-time.Hour)),
	}

	b, err := json.Marshal(overrides)
	require.NoError(t, err)

	overridesFile := filepath.Join(t.TempDir(), "overrides.json")
	require.NoError(t, os.WriteFile(overridesFile, b, 0o644))

	t.Run("overrides newer than the lock win", func(t *testing.T) {
		content, err := proposerConfigGenesis(t.Context(), lock, overridesFile)
		require.NoError(t, err)
		require.Equal(t, []string{
			"0x" + hex.EncodeToString(newer[:]),
			strings.ToLower(lockFees[1]),
			strings.ToLower(lockFees[2]),
		}, content.FeeRecipients(lock))
		require.Equal(t, "200000000", content.DefaultConfig.GasLimit)
		require.Nil(t, content.DefaultConfig.Builder)
	})

	t.Run("absent overrides file", func(t *testing.T) {
		content, err := proposerConfigGenesis(t.Context(), lock, filepath.Join(t.TempDir(), "absent.json"))
		require.NoError(t, err)
		require.Equal(t, lowerAddrs(lockFees), content.FeeRecipients(lock))
	})

	t.Run("invalid overrides file", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.json")
		require.NoError(t, os.WriteFile(bad, []byte("{"), 0o644))

		_, err := proposerConfigGenesis(t.Context(), lock, bad)
		require.ErrorContains(t, err, "unmarshal builder registration overrides file")
	})
}

func TestProposerConfigGenesisMatchesRun(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 3, 3, 4, 0, rand.New(rand.NewSource(1)))

	noRegs := lock
	noRegs.Validators = slices.Clone(lock.Validators)

	for i := range noRegs.Validators {
		noRegs.Validators[i].BuilderRegistration = cluster.BuilderRegistration{}
	}

	b, err := json.Marshal([]*eth2api.VersionedSignedValidatorRegistration{
		signOverride(t, lock, shares, 0, bellatrix.ExecutionAddress{19: 0x99}, time.Now()),
	})
	require.NoError(t, err)

	overridesFile := filepath.Join(t.TempDir(), "overrides.json")
	require.NoError(t, os.WriteFile(overridesFile, b, 0o644))

	// runFeeRecipientFunc is the builder registration service charon run derives genesis from.
	runFeeRecipientFunc := func(t *testing.T, l cluster.Lock) func(core.PubKey) string {
		t.Helper()

		var regs []*eth2api.VersionedSignedValidatorRegistration

		fees := make(map[core.PubKey]string)

		for i, val := range l.Validators {
			pubkey, err := core.PubKeyFromBytes(val.PubKey)
			require.NoError(t, err)

			fees[pubkey] = l.FeeRecipientAddresses()[i]

			reg, err := val.Eth2Registration()
			if err != nil {
				reg = nil
			}

			regs = append(regs, reg)
		}

		svc, err := app.NewBuilderRegistrationService(t.Context(), overridesFile, eth2p0.Version(l.ForkVersion), regs, fees, nil, l.LockHash)
		require.NoError(t, err)

		return svc.FeeRecipient
	}

	for name, l := range map[string]cluster.Lock{"with registrations": lock, "without registrations": noRegs} {
		t.Run(name, func(t *testing.T) {
			got, err := proposerConfigGenesis(t.Context(), l, overridesFile)
			require.NoError(t, err)

			want, err := app.ProposerConfigGenesis(l, proposerconfig.Seed{GasLimit: proposerconfig.DefaultGasLimit}, runFeeRecipientFunc(t, l))
			require.NoError(t, err)
			require.Equal(t, want.Content, got)
		})
	}
}

func lowerAddrs(addrs []string) []string {
	res := make([]string, 0, len(addrs))
	for _, a := range addrs {
		res = append(res, strings.ToLower(a))
	}

	return res
}

func TestLoadCarriedProposerConfig(t *testing.T) {
	lock, keys, _ := cluster.NewForT(t, 2, 3, 4, 0, rand.New(rand.NewSource(1)))
	nodeIdx := cluster.NodeIdx{PeerIdx: 1, ShareIdx: 2}
	absent := filepath.Join(t.TempDir(), "absent.json")

	content := *testContent(t, lock, 60_000_000)
	content.DefaultConfig.Builder = &proposerconfig.Builder{MinBid: "0", BuilderBoostFactor: "100", MaxExecutionPayment: "0", Builders: []proposerconfig.BuilderEntry{{URL: "https://b.example.com"}}}

	signed := func(t *testing.T, signers int) proposerconfig.Document {
		t.Helper()

		doc := proposerconfig.Document{Version: proposerconfig.Version, LockHash: lock.LockHash, Revision: 3, Content: content}
		for i := range signers {
			sig, err := proposerconfig.Sign(doc, keys[i])
			require.NoError(t, err)

			doc.Signatures = append(doc.Signatures, proposerconfig.Signature{Operator: i, Signature: sig})
		}

		return doc
	}

	write := func(t *testing.T, doc proposerconfig.Document) string {
		t.Helper()

		path := filepath.Join(t.TempDir(), "proposer-config.json")
		require.NoError(t, proposerconfig.Write(path, doc, lock, nodeIdx))

		return path
	}

	t.Run("signed file", func(t *testing.T) {
		got, err := loadCarriedProposerConfig(t.Context(), lock, nodeIdx, write(t, signed(t, lock.Threshold)), absent)
		require.NoError(t, err)
		require.Equal(t, content.FeeRecipients(lock), got.FeeRecipients(lock))
		require.Equal(t, content.DefaultConfig, got.DefaultConfig)
	})

	t.Run("revision 0 file", func(t *testing.T) {
		doc := proposerconfig.Document{Version: proposerconfig.Version, LockHash: lock.LockHash, Content: content}

		got, err := loadCarriedProposerConfig(t.Context(), lock, nodeIdx, write(t, doc), absent)
		require.NoError(t, err)
		require.Equal(t, content.DefaultConfig, got.DefaultConfig)
	})

	t.Run("absent file is genesis", func(t *testing.T) {
		got, err := loadCarriedProposerConfig(t.Context(), lock, nodeIdx, absent, absent)
		require.NoError(t, err)

		want, err := proposerConfigGenesis(t.Context(), lock, absent)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("invalid file", func(t *testing.T) {
		_, err := loadCarriedProposerConfig(t.Context(), lock, nodeIdx, write(t, signed(t, lock.Threshold-1)), absent)
		require.ErrorIs(t, err, proposerconfig.ErrInvalid)
	})

	t.Run("undecodable file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "proposer-config.json")
		require.NoError(t, os.WriteFile(path, []byte("{"), 0o644))

		_, err := loadCarriedProposerConfig(t.Context(), lock, nodeIdx, path, absent)
		require.ErrorContains(t, err, "unmarshal proposer config")
	})

	t.Run("other lock", func(t *testing.T) {
		doc := signed(t, lock.Threshold)
		doc.LockHash = bytes.Repeat([]byte{1}, 32)

		other := lock
		other.LockHash = doc.LockHash

		path := filepath.Join(t.TempDir(), "proposer-config.json")
		require.NoError(t, proposerconfig.Write(path, doc, other, nodeIdx))

		_, err := loadCarriedProposerConfig(t.Context(), lock, nodeIdx, path, absent)
		require.ErrorIs(t, err, proposerconfig.ErrLockHashMismatch)
	})
}

func TestNewLockProposerConfigContent(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 3, 3, 4, 0, rand.New(rand.NewSource(1)))
	carried := lock
	carried.Validators = lock.Validators[:2]

	const (
		defaultFee   = "0x00000000000000000000000000000000000000aa"
		divergingFee = "0x00000000000000000000000000000000000000bb"
		newFee       = "0x00000000000000000000000000000000000000cc"
	)

	builder := &proposerconfig.Builder{MinBid: "1", BuilderBoostFactor: "90", MaxExecutionPayment: "2", Builders: []proposerconfig.BuilderEntry{{URL: "https://b.example.com"}}}

	agreed, err := proposerconfig.NewContent(carried, []string{divergingFee, defaultFee}, 60_000_000, builder)
	require.NoError(t, err)

	t.Run("append", func(t *testing.T) {
		got, err := newLockProposerConfigContent(lock, agreed, 2, []string{newFee})
		require.NoError(t, err)
		require.Equal(t, []string{divergingFee, defaultFee, newFee}, got.FeeRecipients(lock))
		require.Equal(t, "60000000", got.DefaultConfig.GasLimit)
		require.Equal(t, builder, got.DefaultConfig.Builder)
	})

	t.Run("fresh", func(t *testing.T) {
		seed := proposerconfig.Content{DefaultConfig: proposerconfig.Settings{GasLimit: "200000000"}}

		got, err := newLockProposerConfigContent(lock, seed, 0, []string{newFee, newFee, divergingFee})
		require.NoError(t, err)
		require.Equal(t, []string{newFee, newFee, divergingFee}, got.FeeRecipients(lock))
		require.Equal(t, "200000000", got.DefaultConfig.GasLimit)
		require.Nil(t, got.DefaultConfig.Builder)
	})

	t.Run("fee recipient count mismatch", func(t *testing.T) {
		_, err := newLockProposerConfigContent(lock, agreed, 2, nil)
		require.ErrorContains(t, err, "fee recipient count mismatch")
	})
}
