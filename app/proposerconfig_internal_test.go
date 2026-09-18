// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/registration"
)

func TestWriteProposerConfigFile(t *testing.T) {
	const (
		dv      = 4
		nodes   = 4
		peerIdx = 2
	)

	lock, _, _ := cluster.NewForT(t, dv, nodes, nodes, 0, rand.New(rand.NewSource(0)))

	dir := t.TempDir()
	conf := Config{
		LockFile:   filepath.Join(dir, "cluster-lock.json"),
		BuilderAPI: true,
	}
	nodeIdx := cluster.NodeIdx{PeerIdx: peerIdx, ShareIdx: peerIdx + 1}

	path := filepath.Join(dir, proposerConfigDir, proposerConfigFilename)

	// Override the first validator's fee recipient and gas limit (mimicking builder
	// registration overrides), let the second fall back to its lock address, and
	// give the remaining two identical settings so they form the majority.
	overridePubkey, err := core.PubKeyFromBytes(lock.Validators[0].PubKey)
	require.NoError(t, err)

	lockFallbackPubkey, err := core.PubKeyFromBytes(lock.Validators[1].PubKey)
	require.NoError(t, err)

	const (
		overrideAddr = "0xcccccccccccccccccccccccccccccccccccccccc"
		majorityAddr = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)

	feeRecipientFunc := func(pubkey core.PubKey) string {
		switch pubkey {
		case overridePubkey:
			return overrideAddr
		case lockFallbackPubkey:
			return "" // Exercise the lock fallback.
		default:
			return majorityAddr
		}
	}

	const overrideGasLimit = 42_000_000

	gasLimitFunc := func(pubkey core.PubKey) uint64 {
		if pubkey == overridePubkey {
			return overrideGasLimit
		}

		return 0 // Exercise the default fallback for the rest.
	}

	created, err := writeProposerConfigFile(conf, &lock, nodeIdx, feeRecipientFunc, gasLimitFunc)
	require.NoError(t, err)
	require.True(t, created)

	b, err := os.ReadFile(path)
	require.NoError(t, err)

	var config proposerConfigJSON

	require.NoError(t, json.Unmarshal(b, &config))
	require.EqualValues(t, 1, config.Version)

	defaultGasLimit := strconv.FormatUint(registration.DefaultGasLimit, 10)
	feeRecipients := lock.FeeRecipientAddresses()

	pubshare := func(vi int) string {
		share, err := lock.Validators[vi].PublicShare(peerIdx)
		require.NoError(t, err)

		return fmt.Sprintf("%#x", share)
	}

	// The default config holds the majority settings (validators 2 and 3).
	require.Equal(t, majorityAddr, config.DefaultConfig.FeeRecipient)
	require.Equal(t, defaultGasLimit, config.DefaultConfig.GasLimit)

	// The two diverging validators get entries carrying only the diverging fields:
	// validator 0 diverges in both, validator 1 only in its fee recipient.
	require.Len(t, config.ProposerConfig, 2)
	require.Equal(t, proposerSettingsJSON{FeeRecipient: overrideAddr, GasLimit: strconv.FormatUint(overrideGasLimit, 10)}, config.ProposerConfig[pubshare(0)])
	require.Equal(t, proposerSettingsJSON{FeeRecipient: feeRecipients[1]}, config.ProposerConfig[pubshare(1)])

	// No pre-gloas legacy fields in the charon schema.
	require.NotContains(t, string(b), "enabled")
	require.NotContains(t, string(b), "min_bid")

	// An existing file is never modified.
	require.NoError(t, os.WriteFile(path, []byte("operator managed"), 0o644))

	created, err = writeProposerConfigFile(conf, &lock, nodeIdx, feeRecipientFunc, gasLimitFunc)
	require.NoError(t, err)
	require.False(t, created)

	b, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "operator managed", string(b))

	// A directory occupying the file path is an error.
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.Mkdir(path, 0o755))

	_, err = writeProposerConfigFile(conf, &lock, nodeIdx, feeRecipientFunc, gasLimitFunc)
	require.ErrorContains(t, err, "is a directory")
}

func TestGasLimitsByPubkey(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 1, 3, 3, 0, rand.New(rand.NewSource(0)))

	pubkey := eth2p0.BLSPubKey(lock.Validators[0].PubKey)

	corePubkey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)

	regs := []*eth2api.VersionedSignedValidatorRegistration{
		{V1: &eth2v1.SignedValidatorRegistration{Message: &eth2v1.ValidatorRegistration{
			Pubkey:   pubkey,
			GasLimit: 50_000_000,
		}}},
		nil, // Nil and zero gas limit entries are skipped.
		{V1: &eth2v1.SignedValidatorRegistration{Message: &eth2v1.ValidatorRegistration{}}},
	}

	require.Equal(t, map[core.PubKey]uint64{corePubkey: 50_000_000}, gasLimitsByPubkey(regs))
	require.Empty(t, gasLimitsByPubkey(nil))
}
