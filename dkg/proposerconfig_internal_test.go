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

// runAgreement runs agree on all nodes with the given local configs (nil adopts).
func runAgreement(t *testing.T, lock cluster.Lock, locals []*proposerconfig.Config) ([]proposerconfig.Config, []error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	comps, peers, _ := newBcastComponents(t, len(locals))

	var (
		results = make([]proposerconfig.Config, len(locals))
		errs    = make([]error, len(locals))
		eg      errgroup.Group
	)

	agreements := make([]*configAgreement, len(locals))
	for i := range locals {
		agreements[i] = newConfigAgreement(peers, cluster.NodeIdx{PeerIdx: i}, comps[i], proposerConfigContentMsgID)
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

func testProposerConfig(t *testing.T, lock cluster.Lock, gasLimit uint64) *proposerconfig.Config {
	t.Helper()

	fees := make([]string, len(lock.Validators))
	for i := range fees {
		fees[i] = testFeeAddr
	}

	c, err := proposerconfig.NewConfig(lock, fees, gasLimit, nil)
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

func TestConfigAgreementEqual(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 2, 3, 4, 0, rand.New(rand.NewSource(1)))
	c := testProposerConfig(t, lock, proposerconfig.DefaultGasLimit)

	results, errs := runAgreement(t, lock, []*proposerconfig.Config{c, c, c, c})
	for i := range errs {
		require.NoError(t, errs[i])
		require.Equal(t, *c, results[i])
	}
}

func TestConfigAgreementAdopt(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 2, 3, 4, 0, rand.New(rand.NewSource(1)))
	c := testProposerConfig(t, lock, proposerconfig.DefaultGasLimit)

	results, errs := runAgreement(t, lock, []*proposerconfig.Config{nil, c, c, c})
	for i := range errs {
		require.NoError(t, errs[i])
		require.Equal(t, *c, results[i])
	}
}

func TestConfigAgreementAllAdopt(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 1, 3, 4, 0, rand.New(rand.NewSource(1)))

	_, errs := runAgreement(t, lock, []*proposerconfig.Config{nil, nil, nil, nil})
	for _, err := range errs {
		require.ErrorContains(t, err, "no operator has a proposer config")
		require.NotContains(t, err.Error(), "test hint")
	}
}

func TestConfigAgreementMismatchDiff(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 2, 3, 4, 0, rand.New(rand.NewSource(1)))
	a := testProposerConfig(t, lock, proposerconfig.DefaultGasLimit)
	b := testProposerConfig(t, lock, 123)

	_, errs := runAgreement(t, lock, []*proposerconfig.Config{a, a, b, a})
	for _, err := range errs {
		require.ErrorContains(t, err, "peer 2")
		require.ErrorContains(t, err, "default.gas_limit: 200000000 -> 123")
		require.True(t, strings.HasSuffix(err.Error(), "\ntest hint"), err.Error())
		require.NotContains(t, err.Error(), "peer 1")
	}
}

func TestConfigAgreementNoValidators(t *testing.T) {
	// Seed configs carry no validators; Diff must still work against a lock without any.
	a := &proposerconfig.Config{DefaultConfig: proposerconfig.Settings{FeeRecipient: testFeeAddr, GasLimit: "1"}}
	b := &proposerconfig.Config{DefaultConfig: proposerconfig.Settings{FeeRecipient: testFeeAddr, GasLimit: "2"}}

	_, errs := runAgreement(t, cluster.Lock{}, []*proposerconfig.Config{a, b, a})
	for _, err := range errs {
		require.ErrorContains(t, err, "default.gas_limit: 1 -> 2")
	}
}

func TestConfigAgreementNormalisesAddresses(t *testing.T) {
	a := &proposerconfig.Config{DefaultConfig: proposerconfig.Settings{FeeRecipient: testFeeAddr, GasLimit: "1"}}
	b := &proposerconfig.Config{DefaultConfig: proposerconfig.Settings{FeeRecipient: strings.ToLower(testFeeAddr), GasLimit: "1"}}

	_, errs := runAgreement(t, cluster.Lock{}, []*proposerconfig.Config{a, b, a})
	for _, err := range errs {
		require.NoError(t, err)
	}
}

func TestConfigAgreementHostileConfig(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 2, 3, 4, 0, rand.New(rand.NewSource(1)))
	a := testProposerConfig(t, lock, proposerconfig.DefaultGasLimit)
	// Missing default fields, an entry for a pubkey outside the lock and empty maps.
	b := &proposerconfig.Config{ProposerConfig: map[string]proposerconfig.Settings{"0xABCD": {GasLimit: "5"}}}
	c := &proposerconfig.Config{}

	_, errs := runAgreement(t, lock, []*proposerconfig.Config{a, b, c})
	for _, err := range errs {
		require.ErrorContains(t, err, "peer 1")
		require.ErrorContains(t, err, "peer 2")
	}
}

func TestConfigAgreementHashOnlyDiff(t *testing.T) {
	a := &proposerconfig.Config{DefaultConfig: proposerconfig.Settings{FeeRecipient: testFeeAddr, GasLimit: "1"}}
	b := &proposerconfig.Config{
		DefaultConfig:  a.DefaultConfig,
		ProposerConfig: map[string]proposerconfig.Settings{"0xabcd": {GasLimit: "5"}},
	}

	_, errs := runAgreement(t, cluster.Lock{}, []*proposerconfig.Config{a, b, a})
	for _, err := range errs {
		require.ErrorContains(t, err, "configs differ outside the compared fields")
	}
}

func TestConfigAgreementDuplicateFirstWins(t *testing.T) {
	comps, peers, _ := newBcastComponents(t, 2)
	ag := newConfigAgreement(peers, cluster.NodeIdx{PeerIdx: 0}, comps[0], proposerConfigContentMsgID)

	send := func(gas string) error {
		b, err := json.Marshal(proposerconfig.Config{DefaultConfig: proposerconfig.Settings{GasLimit: gas}})
		require.NoError(t, err)

		return ag.broadcastCallback(context.Background(), peers[1].ID, "", &dkgpb.MsgProposerConfigContent{Content: b, PeerIndex: 1})
	}

	require.NoError(t, send("1"))
	require.NoError(t, send("1"))
	require.ErrorContains(t, send("2"), "conflicting")
	require.Equal(t, "1", ag.received[1].DefaultConfig.GasLimit)
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

func TestInitialProposerConfig(t *testing.T) {
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
		cfg, err := initialProposerConfig(t.Context(), lock, overridesFile)
		require.NoError(t, err)
		require.Equal(t, []string{
			"0x" + hex.EncodeToString(newer[:]),
			strings.ToLower(lockFees[1]),
			strings.ToLower(lockFees[2]),
		}, cfg.FeeRecipients(lock))
		require.Equal(t, "200000000", cfg.DefaultConfig.GasLimit)
		require.Nil(t, cfg.DefaultConfig.Builder)
	})

	t.Run("absent overrides file", func(t *testing.T) {
		cfg, err := initialProposerConfig(t.Context(), lock, filepath.Join(t.TempDir(), "absent.json"))
		require.NoError(t, err)
		require.Equal(t, lowerAddrs(lockFees), cfg.FeeRecipients(lock))
	})

	t.Run("invalid overrides file", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.json")
		require.NoError(t, os.WriteFile(bad, []byte("{"), 0o644))

		_, err := initialProposerConfig(t.Context(), lock, bad)
		require.ErrorContains(t, err, "unmarshal builder registration overrides file")
	})
}

func TestInitialProposerConfigMatchesRun(t *testing.T) {
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

	// runFeeRecipientFunc is the builder registration service charon run derives the initial config from.
	runFeeRecipientFunc := func(t *testing.T, l cluster.Lock) func(core.PubKey) string {
		t.Helper()

		var regs []*eth2api.VersionedSignedValidatorRegistration

		fees := make(map[core.PubKey]string)

		for i, val := range l.Validators {
			pubkey, err := core.PubKeyFromBytes(val.PubKey)
			require.NoError(t, err)

			fees[pubkey] = l.FeeRecipientAddresses()[i]

			reg, err := val.Eth2Registration()
			require.NoError(t, err)

			regs = append(regs, reg)
		}

		svc, err := app.NewBuilderRegistrationService(t.Context(), overridesFile, eth2p0.Version(l.ForkVersion), regs, fees, nil, l.LockHash)
		require.NoError(t, err)

		return svc.FeeRecipient
	}

	t.Run("with registrations", func(t *testing.T) {
		got, err := initialProposerConfig(t.Context(), lock, overridesFile)
		require.NoError(t, err)

		want, err := app.InitialProposerConfig(lock, proposerconfig.Seed{GasLimit: proposerconfig.DefaultGasLimit}, runFeeRecipientFunc(t, lock))
		require.NoError(t, err)
		require.Equal(t, want.Config, got)
	})

	t.Run("invalid registration fails as on run", func(t *testing.T) {
		_, err := initialProposerConfig(t.Context(), noRegs, overridesFile)
		require.ErrorContains(t, err, "convert builder registration")
	})
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

	cfg := *testProposerConfig(t, lock, 60_000_000)
	cfg.DefaultConfig.Builder = &proposerconfig.Builder{MinBid: "0", BuilderBoostFactor: "100", MaxExecutionPayment: "0", Builders: []proposerconfig.BuilderEntry{{URL: "https://b.example.com"}}}

	signed := func(t *testing.T, signers int) proposerconfig.Document {
		t.Helper()

		doc := proposerconfig.Document{Version: proposerconfig.Version, LockHash: lock.LockHash, Revision: 3, Config: cfg}
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
		require.Equal(t, cfg.FeeRecipients(lock), got.FeeRecipients(lock))
		require.Equal(t, cfg.DefaultConfig, got.DefaultConfig)
	})

	t.Run("revision 0 file", func(t *testing.T) {
		doc := proposerconfig.Document{Version: proposerconfig.Version, LockHash: lock.LockHash, Config: cfg}

		got, err := loadCarriedProposerConfig(t.Context(), lock, nodeIdx, write(t, doc), absent)
		require.NoError(t, err)
		require.Equal(t, cfg.DefaultConfig, got.DefaultConfig)
	})

	t.Run("absent file is the initial config", func(t *testing.T) {
		got, err := loadCarriedProposerConfig(t.Context(), lock, nodeIdx, absent, absent)
		require.NoError(t, err)

		want, err := initialProposerConfig(t.Context(), lock, absent)
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

	t.Run("unparsable gas limit", func(t *testing.T) {
		bad := cfg
		bad.DefaultConfig.GasLimit = "lots"
		doc := proposerconfig.Document{Version: proposerconfig.Version, LockHash: lock.LockHash, Config: bad}

		_, err := loadCarriedProposerConfig(t.Context(), lock, nodeIdx, write(t, doc), absent)
		require.ErrorContains(t, err, "parse gas limit")
	})

	t.Run("unparsable builder field", func(t *testing.T) {
		bad := cfg
		bad.DefaultConfig.Builder = &proposerconfig.Builder{MinBid: "lots", BuilderBoostFactor: "100", MaxExecutionPayment: "0", Builders: cfg.DefaultConfig.Builder.Builders}
		doc := proposerconfig.Document{Version: proposerconfig.Version, LockHash: lock.LockHash, Config: bad}

		_, err := loadCarriedProposerConfig(t.Context(), lock, nodeIdx, write(t, doc), absent)
		require.ErrorContains(t, err, "parse builder min_bid")
	})

	t.Run("builder URL without a scheme", func(t *testing.T) {
		bad := cfg
		bad.DefaultConfig.Builder = &proposerconfig.Builder{MinBid: "0", BuilderBoostFactor: "100", MaxExecutionPayment: "0", Builders: []proposerconfig.BuilderEntry{{URL: "b.example.com"}}}
		doc := proposerconfig.Document{Version: proposerconfig.Version, LockHash: lock.LockHash, Config: bad}

		_, err := loadCarriedProposerConfig(t.Context(), lock, nodeIdx, write(t, doc), absent)
		require.ErrorContains(t, err, "builder URL has no scheme")
	})

	malformedOverrides := func(t *testing.T) string {
		t.Helper()

		path := filepath.Join(t.TempDir(), "overrides.json")
		require.NoError(t, os.WriteFile(path, []byte("{"), 0o644))

		return path
	}

	t.Run("malformed overrides file without a proposer config file", func(t *testing.T) {
		_, err := loadCarriedProposerConfig(t.Context(), lock, nodeIdx, absent, malformedOverrides(t))
		require.ErrorContains(t, err, "unmarshal builder registration overrides file")
	})

	t.Run("overrides file ignored with a proposer config file", func(t *testing.T) {
		doc := proposerconfig.Document{Version: proposerconfig.Version, LockHash: lock.LockHash, Config: cfg}

		got, err := loadCarriedProposerConfig(t.Context(), lock, nodeIdx, write(t, doc), malformedOverrides(t))
		require.NoError(t, err)
		require.Equal(t, cfg.DefaultConfig, got.DefaultConfig)
	})
}

// TestCarriedProposerConfigScenarios covers operators running a lock-changing edit in mixed proposer config
// states: each operator's carried config is loaded as initProposerConfig does and the agreement resolved
// over them. Only the content counts: revisions are not compared and the overrides file is only read
// by an operator without a proposer config file.
func TestCarriedProposerConfigScenarios(t *testing.T) {
	lock, keys, shares := cluster.NewForT(t, 2, 3, 4, 0, rand.New(rand.NewSource(1)))

	const (
		overrideFee = "0x0000000000000000000000000000000000000099"
		builderURL  = "https://b.example.com"
	)

	newConfig := func(fees []string, gasLimit uint64, builder *proposerconfig.Builder) proposerconfig.Config {
		cfg, err := proposerconfig.NewConfig(lock, fees, gasLimit, builder)
		require.NoError(t, err)

		return cfg
	}

	builder := &proposerconfig.Builder{MinBid: "0", BuilderBoostFactor: "100", MaxExecutionPayment: "0", Builders: []proposerconfig.BuilderEntry{{URL: builderURL}}}

	lockFees := lowerAddrs(lock.FeeRecipientAddresses())
	overriddenFees := slices.Clone(lockFees)
	overriddenFees[0] = overrideFee

	var (
		initial    = newConfig(lockFees, proposerconfig.DefaultGasLimit, nil)       // charon run without overrides and seeding flags.
		overridden = newConfig(overriddenFees, proposerconfig.DefaultGasLimit, nil) // charon run with the override.
		edited     = newConfig(lockFees, 60_000_000, builder)                       // Seeding flags or an edit ceremony.
		edited2    = newConfig(lockFees, 70_000_000, builder)                       // A later edit ceremony.
	)

	b, err := json.Marshal([]*eth2api.VersionedSignedValidatorRegistration{
		signOverride(t, lock, shares, 0, bellatrix.ExecutionAddress{19: 0x99}, time.Now()),
	})
	require.NoError(t, err)

	overridesFile := filepath.Join(t.TempDir(), "overrides.json")
	require.NoError(t, os.WriteFile(overridesFile, b, 0o644))

	absent := filepath.Join(t.TempDir(), "absent.json")

	doc := func(revision uint64, cfg proposerconfig.Config, signers int) *proposerconfig.Document {
		d := proposerconfig.Document{Version: proposerconfig.Version, LockHash: lock.LockHash, Revision: revision, Config: cfg}
		for i := range signers {
			sig, err := proposerconfig.Sign(d, keys[i])
			require.NoError(t, err)

			d.Signatures = append(d.Signatures, proposerconfig.Signature{Operator: i, Signature: sig})
		}

		return &d
	}

	// state is an operator's proposer config file (nil for none) and overrides file.
	type state struct {
		doc       *proposerconfig.Document
		overrides string
	}

	states := map[string]state{
		"no file":                  {overrides: absent},
		"no file, override":        {overrides: overridesFile},
		"rev 0":                    {doc: doc(0, initial, 0), overrides: absent},
		"rev 0, override baked in": {doc: doc(0, overridden, 0), overrides: overridesFile},
		"rev 0, override added":    {doc: doc(0, initial, 0), overrides: overridesFile},
		"rev 0, seeded":            {doc: doc(0, edited, 0), overrides: absent},
		"rev 1":                    {doc: doc(1, edited, lock.Threshold), overrides: absent},
		"rev 1, override":          {doc: doc(1, edited, lock.Threshold), overrides: overridesFile},
		"rev 1, initial content":   {doc: doc(1, initial, len(lock.Operators)), overrides: absent},
		"rev 2":                    {doc: doc(2, edited2, lock.Threshold), overrides: absent},
	}

	feeField := "validator 0x" + hex.EncodeToString(lock.Validators[0].PubKey) + ".fee_recipient"

	tests := []struct {
		name        string
		operators   [4]string
		want        proposerconfig.Config
		errLines    []string
		absentLines []string
	}{
		{
			name:      "no files",
			operators: [4]string{"no file", "no file", "no file", "no file"},
			want:      initial,
		},
		{
			name:      "no files, same override",
			operators: [4]string{"no file, override", "no file, override", "no file, override", "no file, override"},
			want:      overridden,
		},
		{
			name:      "no files, override on one operator",
			operators: [4]string{"no file", "no file, override", "no file", "no file"},
			errLines:  []string{"peer 1 differs from peer 0", feeField + ": " + lockFees[0] + " -> " + overrideFee},
		},
		{
			name:      "rev 0 next to no file",
			operators: [4]string{"rev 0", "no file", "rev 0", "no file"},
			want:      initial,
		},
		{
			name:      "rev 0 with the override baked in next to rev 0 without",
			operators: [4]string{"rev 0", "rev 0, override baked in", "rev 0", "rev 0"},
			errLines:  []string{"peer 1 differs from peer 0", feeField + ": " + lockFees[0] + " -> " + overrideFee},
		},
		{
			name:      "override added after rev 0 is ignored",
			operators: [4]string{"rev 0, override added", "rev 0", "no file", "rev 0"},
			want:      initial,
		},
		{
			name:      "rev 0 with the override baked in next to no file with the override",
			operators: [4]string{"rev 0, override baked in", "no file, override", "rev 0, override baked in", "no file, override"},
			want:      overridden,
		},
		{
			name:        "rev 0 from seeding flags next to no file",
			operators:   [4]string{"no file", "rev 0, seeded", "no file", "no file"},
			errLines:    []string{"peer 1 differs from peer 0", "default.gas_limit: 200000000 -> 60000000", "default.builder.urls: none -> "},
			absentLines: []string{feeField},
		},
		{
			name:      "rev 0 next to rev 1",
			operators: [4]string{"rev 1", "rev 1", "rev 0", "rev 1"},
			errLines:  []string{"peer 2 differs from peer 0", "default.gas_limit: 60000000 -> 200000000"},
		},
		{
			name:      "rev 1 next to rev 2",
			operators: [4]string{"rev 2", "rev 1", "rev 2", "rev 2"},
			errLines:  []string{"peer 1 differs from peer 0", "default.gas_limit: 70000000 -> 60000000"},
		},
		{
			name:      "rev 1 with the initial content next to rev 0",
			operators: [4]string{"rev 1, initial content", "rev 0", "no file", "rev 0"},
			want:      initial,
		},
		{
			name:      "override next to rev 1 is ignored",
			operators: [4]string{"rev 1, override", "rev 1", "rev 1", "rev 1"},
			want:      edited,
		},
		{
			name:      "rev 1 next to rev 0 with the override baked in",
			operators: [4]string{"rev 1, override", "rev 0, override baked in", "rev 1", "rev 1"},
			errLines:  []string{"peer 1 differs from peer 0", "default.gas_limit: 60000000 -> 200000000", feeField + ": " + lockFees[0] + " -> " + overrideFee},
		},
		{
			name:        "rev 1 next to rev 0 without the override",
			operators:   [4]string{"rev 1", "rev 0", "rev 1", "rev 1"},
			errLines:    []string{"peer 1 differs from peer 0", "default.gas_limit: 60000000 -> 200000000"},
			absentLines: []string{feeField},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			locals := make([]*proposerconfig.Config, len(test.operators))

			for i, name := range test.operators {
				st, ok := states[name]
				require.True(t, ok, name)

				nodeIdx := cluster.NodeIdx{PeerIdx: i, ShareIdx: i + 1}

				path := filepath.Join(t.TempDir(), "proposer-config.json")
				if st.doc != nil {
					require.NoError(t, proposerconfig.Write(path, *st.doc, lock, nodeIdx))
				}

				cfg, err := loadCarriedProposerConfig(t.Context(), lock, nodeIdx, path, st.overrides)
				require.NoError(t, err)

				norm, err := proposerconfig.Normalise(cfg)
				require.NoError(t, err)

				locals[i] = &norm
			}

			got, err := resolveConfigs(lock, locals, proposerConfigCarriedHint)
			if len(test.errLines) == 0 {
				require.NoError(t, err)

				same, err := proposerconfig.SameConfig(test.want, got)
				require.NoError(t, err)
				require.True(t, same)

				return
			}

			require.ErrorContains(t, err, "proposer config mismatch between operators")

			for _, line := range test.errLines {
				require.ErrorContains(t, err, line)
			}

			for _, line := range test.absentLines {
				require.NotContains(t, err.Error(), line)
			}

			require.ErrorContains(t, err, proposerConfigCarriedHint)
		})
	}
}

// TestInitProposerConfig verifies adopting operators (joining or removed) never read their proposer config
// file, while remaining operators fail fast on an unusable one.
func TestInitProposerConfig(t *testing.T) {
	lock, keys, _ := cluster.NewForT(t, 2, 3, 4, 0, rand.New(rand.NewSource(1)))
	comps, peers, _ := newBcastComponents(t, 4)

	peerID, err := p2p.PeerIDFromKey(keys[1].PubKey())
	require.NoError(t, err)

	joiningKey, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	joiningID, err := p2p.PeerIDFromKey(joiningKey.PubKey())
	require.NoError(t, err)

	garbage := filepath.Join(t.TempDir(), "proposer-config.json")
	require.NoError(t, os.WriteFile(garbage, []byte("{"), 0o644))

	absent := filepath.Join(t.TempDir(), "absent.json")

	newPctx := func(comp *bcast.Component, peerID peer.ID) *ProtocolContext {
		return &ProtocolContext{Lock: &lock, ThisPeerID: peerID, ThisNodeIdx: cluster.NodeIdx{PeerIdx: 1, ShareIdx: 2}, Peers: peers, Caster: comp}
	}

	t.Run("joining adopts and ignores the file", func(t *testing.T) {
		pctx := newPctx(comps[0], joiningID)
		require.NoError(t, initProposerConfig(t.Context(), pctx, garbage, garbage, false))
		require.Nil(t, pctx.proposerConfigLocal)
		require.NotNil(t, pctx.ProposerConfig)
		require.NotNil(t, pctx.ProposerConfigSigCaster)
	})

	t.Run("removed adopts and ignores the file", func(t *testing.T) {
		pctx := newPctx(comps[1], peerID)
		require.NoError(t, initProposerConfig(t.Context(), pctx, garbage, garbage, true))
		require.Nil(t, pctx.proposerConfigLocal)
	})

	t.Run("remaining fails on an unusable file", func(t *testing.T) {
		pctx := newPctx(comps[2], peerID)
		require.ErrorContains(t, initProposerConfig(t.Context(), pctx, garbage, absent, false), "unmarshal proposer config")
	})

	t.Run("remaining carries the file", func(t *testing.T) {
		pctx := newPctx(comps[3], peerID)
		require.NoError(t, initProposerConfig(t.Context(), pctx, absent, absent, false))
		require.NotNil(t, pctx.proposerConfigLocal)
	})
}

func TestNewLockProposerConfig(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 3, 3, 4, 0, rand.New(rand.NewSource(1)))
	carried := lock
	carried.Validators = lock.Validators[:2]

	const (
		defaultFee   = "0x00000000000000000000000000000000000000aa"
		divergingFee = "0x00000000000000000000000000000000000000bb"
		newFee       = "0x00000000000000000000000000000000000000cc"
	)

	builder := &proposerconfig.Builder{MinBid: "1", BuilderBoostFactor: "90", MaxExecutionPayment: "2", Builders: []proposerconfig.BuilderEntry{{URL: "https://b.example.com"}}}

	agreed, err := proposerconfig.NewConfig(carried, []string{divergingFee, defaultFee}, 60_000_000, builder)
	require.NoError(t, err)

	t.Run("append", func(t *testing.T) {
		got, err := newLockProposerConfig(lock, agreed, carried, []string{newFee})
		require.NoError(t, err)
		require.Equal(t, []string{divergingFee, defaultFee, newFee}, got.FeeRecipients(lock))
		require.Equal(t, "60000000", got.DefaultConfig.GasLimit)
		require.Equal(t, builder, got.DefaultConfig.Builder)
	})

	t.Run("fresh", func(t *testing.T) {
		seed := proposerconfig.Config{DefaultConfig: proposerconfig.Settings{GasLimit: "200000000"}}

		got, err := newLockProposerConfig(lock, seed, cluster.Lock{}, []string{newFee, newFee, divergingFee})
		require.NoError(t, err)
		require.Equal(t, []string{newFee, newFee, divergingFee}, got.FeeRecipients(lock))
		require.Equal(t, "200000000", got.DefaultConfig.GasLimit)
		require.Nil(t, got.DefaultConfig.Builder)
	})

	t.Run("fee recipient count mismatch", func(t *testing.T) {
		_, err := newLockProposerConfig(lock, agreed, carried, nil)
		require.ErrorContains(t, err, "fee recipient count mismatch")
	})
}
