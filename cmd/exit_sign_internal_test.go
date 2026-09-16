// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/electra"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
	"github.com/obolnetwork/charon/testutil/obolapimock"
)

func writeAllLockData(
	t *testing.T,
	root string,
	enrs []*k1.PrivateKey,
	operatorShares [][]tbls.PrivateKey,
	manifestBytes []byte,
) {
	t.Helper()

	for opIdx := range enrs {
		opID := fmt.Sprintf("op%d", opIdx)
		oDir := filepath.Join(root, opID)
		keysDir := filepath.Join(oDir, "validator_keys")
		manifestFile := filepath.Join(oDir, "cluster-lock.json")

		require.NoError(t, os.MkdirAll(oDir, 0o755))
		require.NoError(t, k1util.Save(enrs[opIdx], filepath.Join(oDir, "charon-enr-private-key")))

		require.NoError(t, os.MkdirAll(keysDir, 0o755))

		require.NoError(t, keystore.StoreKeysInsecure(operatorShares[opIdx], keysDir, keystore.ConfirmInsecureKeys))
		require.NoError(t, os.WriteFile(manifestFile, manifestBytes, 0o755))
	}
}

func Test_runSubmitPartialExit(t *testing.T) {
	t.Run("main flow with bad pubkey", func(t *testing.T) {
		runSubmitPartialExitFlowTest(
			t,
			false,
			false,
			"test",
			0,
			"convert core pubkey to eth2 pubkey",
			false,
		)
	})

	t.Run("main flow with pubkey not found in cluster lock", func(t *testing.T) {
		runSubmitPartialExitFlowTest(
			t,
			false,
			false,
			testutil.RandomEth2PubKey(t).String(),
			0,
			"validator not present in cluster lock",
			false,
		)
	})

	t.Run("main flow with validator index set not found in cluster lock", func(t *testing.T) {
		runSubmitPartialExitFlowTest(
			t,
			true,
			false,
			"",
			9999,
			"validator index not found in beacon node response",
			false,
		)
	})

	t.Run("main flow with skipBeaconNodeCheck mode with bad pubkey", func(t *testing.T) {
		runSubmitPartialExitFlowTest(
			t,
			true,
			true,
			"test",
			9999,
			"convert core pubkey to eth2 pubkey",
			false,
		)
	})

	t.Run("main flow with skipBeaconNodeCheck mode with pubkey not found in cluster lock", func(t *testing.T) {
		runSubmitPartialExitFlowTest(
			t,
			true,
			true,
			testutil.RandomEth2PubKey(t).String(),
			9999,
			"validator not present in cluster lock",
			false,
		)
	})

	t.Run("main flow with pubkey", func(t *testing.T) {
		runSubmitPartialExitFlowTest(t, false, false, "", 0, "", false)
	})
	t.Run("main flow with validator index", func(t *testing.T) {
		runSubmitPartialExitFlowTest(t, true, false, "", 0, "", false)
	})
	t.Run("main flow with skipBeaconNodeCheck mode", func(t *testing.T) {
		runSubmitPartialExitFlowTest(t, true, true, "", 0, "", false)
	})
	t.Run("main flow with all mode", func(t *testing.T) {
		runSubmitPartialExitFlowTest(t, false, false, "", 0, "", true)
	})

	t.Run("config", Test_runSubmitPartialExit_Config)
}

func runSubmitPartialExitFlowTest(t *testing.T, useValIdx bool, skipBeaconNodeCheck bool, valPubkey string, valIndex uint64, errString string, all bool) {
	t.Helper()

	ctx := t.Context()
	ctx = log.WithCtx(ctx, z.Str("test_case", t.Name()))

	valAmt := 100
	operatorAmt := 4

	random := rand.New(rand.NewSource(int64(0)))

	lock, enrs, keyShares := cluster.NewForT(
		t,
		valAmt,
		operatorAmt,
		operatorAmt,
		0,
		random,
	)

	root := t.TempDir()

	operatorShares := make([][]tbls.PrivateKey, operatorAmt)

	for opIdx := range operatorAmt {
		for _, share := range keyShares {
			operatorShares[opIdx] = append(operatorShares[opIdx], share[opIdx])
		}
	}

	mBytes, err := json.Marshal(lock)
	require.NoError(t, err)

	validatorSet := beaconmock.ValidatorSet{}

	for idx, v := range lock.Validators {
		validatorSet[eth2p0.ValidatorIndex(idx)] = &eth2v1.Validator{
			Index:   eth2p0.ValidatorIndex(idx),
			Balance: 42,
			Status:  eth2v1.ValidatorStateActiveOngoing,
			Validator: &eth2p0.Validator{
				PublicKey:             eth2p0.BLSPubKey(v.PubKey),
				WithdrawalCredentials: testutil.RandomBytes32(),
			},
		}
	}

	beaconMock, err := beaconmock.New(t.Context(), beaconmock.WithValidatorSet(validatorSet))
	require.NoError(t, err)

	defer func() {
		require.NoError(t, beaconMock.Close())
	}()

	eth2Cl, err := eth2Client(ctx, []string{}, map[string]string{}, []string{beaconMock.Address()}, 10*time.Second, [4]byte(lock.ForkVersion))
	require.NoError(t, err)

	handler, addLockFiles := obolapimock.MockServer(false, eth2Cl)
	srv := httptest.NewServer(handler)

	addLockFiles(lock)

	defer srv.Close()

	writeAllLockData(t, root, enrs, operatorShares, mBytes)

	baseDir := filepath.Join(root, fmt.Sprintf("op%d", 0))

	config := exitConfig{
		BeaconNodeEndpoints: []string{beaconMock.Address()},
		PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
		ValidatorKeysDir:    filepath.Join(baseDir, "validator_keys"),
		LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
		PublishAddress:      srv.URL,
		ExitEpoch:           194048,
		BeaconNodeTimeout:   30 * time.Second,
		PublishTimeout:      10 * time.Second,
		All:                 all,
	}

	index := uint64(0)
	pubkey := lock.Validators[0].PublicKeyHex()

	if valIndex != 0 {
		index = valIndex
	}

	if valPubkey != "" {
		pubkey = valPubkey
	}

	if skipBeaconNodeCheck {
		config.ValidatorIndex = index
		config.ValidatorIndexPresent = true
		config.ValidatorPubkey = pubkey
		config.SkipBeaconNodeCheck = true
	} else {
		if useValIdx {
			config.ValidatorIndex = index
			config.ValidatorIndexPresent = true
		} else {
			config.ValidatorPubkey = pubkey
		}
	}

	if errString != "" {
		require.ErrorContains(t, runSignPartialExit(ctx, config), errString)
		return
	}

	require.NoError(t, runSignPartialExit(ctx, config))
}

func Test_runSubmitPartialExit_Config(t *testing.T) {
	type test struct {
		name                   string
		noIdentity             bool
		noLock                 bool
		noKeystore             bool
		badOAPIURL             bool
		badBeaconNodeEndpoints bool
		badValidatorAddr       bool
		errData                string
	}

	tests := []test{
		{
			name:       "No identity key",
			noIdentity: true,
			errData:    "load identity key",
		},
		{
			name:    "No cluster lock",
			noLock:  true,
			errData: "no such file or directory",
		},
		{
			name:       "No keystore",
			noKeystore: true,
			errData:    "load keystore",
		},
		{
			name:       "Bad Obol API URL",
			badOAPIURL: true,
			errData:    "create Obol API client",
		},
		{
			name:                   "Bad beacon node URL",
			badBeaconNodeEndpoints: true,
			errData:                "create eth2 client for specified beacon node",
		},
		{
			name:             "Bad validator address",
			badValidatorAddr: true,
			errData:          "convert core pubkey to eth2 pubkey",
		},
	}

	del := func(t *testing.T, tc test, root string, opIdx int) {
		t.Helper()

		opID := fmt.Sprintf("op%d", opIdx)
		oDir := filepath.Join(root, opID)

		switch {
		case tc.noLock:
			require.NoError(t, os.RemoveAll(filepath.Join(oDir, "cluster-lock.json")))
		case tc.noKeystore:
			require.NoError(t, os.RemoveAll(filepath.Join(oDir, "validator_keys")))
		case tc.noIdentity:
			require.NoError(t, os.RemoveAll(filepath.Join(oDir, "charon-enr-private-key")))
		}
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()

			valAmt := 100
			operatorAmt := 4

			random := rand.New(rand.NewSource(int64(0)))

			lock, enrs, keyShares := cluster.NewForT(
				t,
				valAmt,
				operatorAmt,
				operatorAmt,
				0,
				random,
			)

			root := t.TempDir()

			operatorShares := make([][]tbls.PrivateKey, operatorAmt)

			for opIdx := range operatorAmt {
				for _, share := range keyShares {
					operatorShares[opIdx] = append(operatorShares[opIdx], share[opIdx])
				}
			}

			mBytes, err := json.Marshal(lock)
			require.NoError(t, err)

			writeAllLockData(t, root, enrs, operatorShares, mBytes)

			for opIdx := range operatorAmt {
				del(t, test, root, opIdx)
			}

			bnURL := badStr

			if !test.badBeaconNodeEndpoints {
				beaconMock, err := beaconmock.New(t.Context())
				require.NoError(t, err)

				t.Cleanup(func() {
					require.NoError(t, beaconMock.Close())
				})

				bnURL = beaconMock.Address()
			}

			oapiURL := badStr
			if !test.badOAPIURL {
				oapiURL = "https://api.obol.tech/v1"
			}

			valAddr := badStr
			if !test.badValidatorAddr {
				valAddr = lock.Validators[0].PublicKeyHex()
			}

			baseDir := filepath.Join(root, fmt.Sprintf("op%d", 0))

			config := exitConfig{
				BeaconNodeEndpoints: []string{bnURL},
				ValidatorPubkey:     valAddr,
				PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
				ValidatorKeysDir:    filepath.Join(baseDir, "validator_keys"),
				LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
				PublishAddress:      oapiURL,
				ExitEpoch:           0,
				BeaconNodeTimeout:   30 * time.Second,
				PublishTimeout:      10 * time.Second,
			}

			require.ErrorContains(t, runSignPartialExit(ctx, config), test.errData)
		})
	}
}

func TestExitSignCLI(t *testing.T) {
	tests := []struct {
		name        string
		expectedErr string
		flags       []string
	}{
		{
			name:        "check flags",
			expectedErr: "load identity key: read private key from disk: open test: no such file or directory",
			flags: []string{
				"--publish-address=test",
				"--private-key-file=test",
				"--lock-file=test",
				"--validator-keys-dir=test",
				"--exit-epoch=1",
				"--validator-public-key=test",
				"--validator-index=1",
				"--beacon-node-endpoints=test1,test2",
				"--beacon-node-timeout=1ms",
				"--publish-timeout=1ms",
				"--all=false",
				"--testnet-name=test",
				"--testnet-fork-version=test",
				"--testnet-chain-id=1",
				"--testnet-genesis-timestamp=1",
				"--testnet-capella-hard-fork=test",
			},
		},
		{
			name:        "no pubkey, no index, single validator",
			expectedErr: "either validator-index or validator-public-key must be specified at least when exiting single validator.",
			flags: []string{
				"--publish-address=test",
				"--private-key-file=test",
				"--lock-file=test",
				"--validator-keys-dir=test",
				"--exit-epoch=1",
				"--beacon-node-endpoints=test1,test2",
				"--beacon-node-timeout=1ms",
				"--publish-timeout=1ms",
				"--all=false",
				"--testnet-name=test",
				"--testnet-fork-version=test",
				"--testnet-chain-id=1",
				"--testnet-genesis-timestamp=1",
				"--testnet-capella-hard-fork=test",
			},
		},
		{
			name:        "pubkey present, all validators",
			expectedErr: "validator-index or validator-public-key should not be specified when all is, as they are obsolete and misleading.",
			flags: []string{
				"--publish-address=test",
				"--private-key-file=test",
				"--lock-file=test",
				"--validator-keys-dir=test",
				"--exit-epoch=1",
				"--validator-public-key=test",
				"--beacon-node-endpoints=test1,test2",
				"--beacon-node-timeout=1ms",
				"--publish-timeout=1ms",
				"--all=true",
				"--testnet-name=test",
				"--testnet-fork-version=test",
				"--testnet-chain-id=1",
				"--testnet-genesis-timestamp=1",
				"--testnet-capella-hard-fork=test",
			},
		},
		{
			name:        "index present, all validators",
			expectedErr: "validator-index or validator-public-key should not be specified when all is, as they are obsolete and misleading.",
			flags: []string{
				"--publish-address=test",
				"--private-key-file=test",
				"--lock-file=test",
				"--validator-keys-dir=test",
				"--exit-epoch=1",
				"--validator-index=1",
				"--beacon-node-endpoints=test1,test2",
				"--beacon-node-timeout=1ms",
				"--publish-timeout=1ms",
				"--all=true",
				"--testnet-name=test",
				"--testnet-fork-version=test",
				"--testnet-chain-id=1",
				"--testnet-genesis-timestamp=1",
				"--testnet-capella-hard-fork=test",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := newExitCmd(newSignPartialExitCmd(runSignPartialExit))
			cmd.SetArgs(append([]string{"sign"}, test.flags...))

			err := cmd.Execute()
			if test.expectedErr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, test.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func Test_pendingDepositsWithoutIndex(t *testing.T) {
	pk := func(b byte) eth2p0.BLSPubKey {
		var out eth2p0.BLSPubKey

		out[0] = b

		return out
	}

	clusterA, clusterB, clusterC := pk(1), pk(2), pk(3)
	nonCluster := pk(9)

	deposit := func(p eth2p0.BLSPubKey) *electra.PendingDeposit {
		return &electra.PendingDeposit{Pubkey: p}
	}

	tests := []struct {
		name            string
		cluster         []eth2p0.BLSPubKey
		indexed         []eth2p0.BLSPubKey
		pendingDeposits []*electra.PendingDeposit
		want            []eth2p0.BLSPubKey
	}{
		{
			name:            "deposit registered but no index yet",
			cluster:         []eth2p0.BLSPubKey{clusterA, clusterB},
			indexed:         nil,
			pendingDeposits: []*electra.PendingDeposit{deposit(clusterA)},
			want:            []eth2p0.BLSPubKey{clusterA},
		},
		{
			name:            "top-up deposit for indexed validator is ignored",
			cluster:         []eth2p0.BLSPubKey{clusterA},
			indexed:         []eth2p0.BLSPubKey{clusterA},
			pendingDeposits: []*electra.PendingDeposit{deposit(clusterA)},
			want:            nil,
		},
		{
			name:            "deposit for non-cluster validator is ignored",
			cluster:         []eth2p0.BLSPubKey{clusterA},
			indexed:         nil,
			pendingDeposits: []*electra.PendingDeposit{deposit(nonCluster)},
			want:            nil,
		},
		{
			name:            "empty queue yields nothing",
			cluster:         []eth2p0.BLSPubKey{clusterA},
			indexed:         nil,
			pendingDeposits: nil,
			want:            nil,
		},
		{
			name:            "multiple deposits for same validator deduplicated",
			cluster:         []eth2p0.BLSPubKey{clusterA},
			indexed:         nil,
			pendingDeposits: []*electra.PendingDeposit{deposit(clusterA), deposit(clusterA)},
			want:            []eth2p0.BLSPubKey{clusterA},
		},
		{
			name:            "results sorted deterministically",
			cluster:         []eth2p0.BLSPubKey{clusterA, clusterB, clusterC},
			indexed:         nil,
			pendingDeposits: []*electra.PendingDeposit{deposit(clusterC), deposit(clusterA), deposit(clusterB)},
			want:            []eth2p0.BLSPubKey{clusterA, clusterB, clusterC},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clusterSet := make(map[eth2p0.BLSPubKey]bool)
			for _, p := range test.cluster {
				clusterSet[p] = true
			}

			indexedSet := make(map[eth2p0.BLSPubKey]bool)
			for _, p := range test.indexed {
				indexedSet[p] = true
			}

			got := pendingDepositsWithoutIndex(clusterSet, indexedSet, test.pendingDeposits)
			require.Equal(t, test.want, got)
		})
	}
}

// mixedValidatorSet builds a cluster and a beacon validator set where the validators
// are split across states: active_ongoing, pending_initialized (has an index) and
// entirely absent from the beacon (no index). The absent validators' public keys are
// returned so callers can place them in the pending-deposits queue.
func mixedValidatorSet(t *testing.T) (keystore.ValidatorShares, beaconmock.ValidatorSet, []eth2p0.BLSPubKey) {
	t.Helper()

	const (
		valAmt      = 3
		operatorAmt = 4
	)

	random := rand.New(rand.NewSource(int64(0)))

	lock, _, keyShares := cluster.NewForT(t, valAmt, operatorAmt, operatorAmt, 0, random)

	shares := make(keystore.ValidatorShares)

	for i, v := range lock.Validators {
		pk, err := core.PubKeyFromBytes(v.PubKey)
		require.NoError(t, err)

		shares[pk] = keystore.IndexedKeyShare{Share: keyShares[i][0], Index: i}
	}

	validatorSet := beaconmock.ValidatorSet{}
	// index 0: active_ongoing, index 1: pending_initialized, index 2: absent (no index).
	states := []eth2v1.ValidatorState{eth2v1.ValidatorStateActiveOngoing, eth2v1.ValidatorStatePendingInitialized}

	var noIndex []eth2p0.BLSPubKey

	for idx, v := range lock.Validators {
		if idx >= len(states) {
			noIndex = append(noIndex, eth2p0.BLSPubKey(v.PubKey))
			continue
		}

		validatorSet[eth2p0.ValidatorIndex(idx)] = &eth2v1.Validator{
			Index:   eth2p0.ValidatorIndex(idx),
			Balance: 42,
			Status:  states[idx],
			Validator: &eth2p0.Validator{
				PublicKey:             eth2p0.BLSPubKey(v.PubKey),
				WithdrawalCredentials: testutil.RandomBytes32(),
			},
		}
	}

	return shares, validatorSet, noIndex
}

// stateFilteringValidators overrides a beacon mock's ValidatorsFunc to emulate a real beacon
// node: it returns only validators whose status is among the requested states (and, when set,
// whose public key is requested). This lets tests exercise the state filter that the plain
// WithValidatorSet mock ignores.
func stateFilteringValidators(set beaconmock.ValidatorSet) func(context.Context, *eth2api.ValidatorsOpts) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
	return func(_ context.Context, opts *eth2api.ValidatorsOpts) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
		resp := make(map[eth2p0.ValidatorIndex]*eth2v1.Validator)

		for idx, val := range set {
			if len(opts.ValidatorStates) > 0 && !slices.Contains(opts.ValidatorStates, val.Status) {
				continue
			}

			if len(opts.PubKeys) > 0 && !slices.Contains(opts.PubKeys, val.Validator.PublicKey) {
				continue
			}

			resp[idx] = val
		}

		return resp, nil
	}
}

func Test_signAllValidatorsExits_signsPendingInitialized(t *testing.T) {
	ctx := t.Context()

	shares, validatorSet, noIndex := mixedValidatorSet(t)

	beaconMock, err := beaconmock.New(ctx, beaconmock.WithValidatorSet(validatorSet))
	require.NoError(t, err)

	t.Cleanup(func() { require.NoError(t, beaconMock.Close()) })

	beaconMock.ValidatorsFunc = stateFilteringValidators(validatorSet)

	// The no-index validator sits in the pending-deposits queue: it triggers the warning but
	// must not affect signing of the exitable validators.
	beaconMock.PendingDepositsFunc = func(context.Context, *eth2api.PendingDepositsOpts) ([]*electra.PendingDeposit, error) {
		return []*electra.PendingDeposit{{Pubkey: noIndex[0]}}, nil
	}

	config := exitConfig{ExitEpoch: 194048}

	exitBlobs, err := signAllValidatorsExits(ctx, config, beaconMock, shares)
	require.NoError(t, err)

	// active_ongoing and pending_initialized are signed; the no-index validator is not.
	require.Len(t, exitBlobs, 2)

	signed := make(map[string]bool)
	for _, b := range exitBlobs {
		signed[b.PublicKey] = true
	}

	require.False(t, signed[noIndex[0].String()], "no-index validator must not be signed")
}

func Test_pendingDepositWarnings(t *testing.T) {
	ctx := t.Context()

	shares, validatorSet, noIndex := mixedValidatorSet(t)

	beaconMock, err := beaconmock.New(ctx, beaconmock.WithValidatorSet(validatorSet))
	require.NoError(t, err)

	t.Cleanup(func() { require.NoError(t, beaconMock.Close()) })

	activePubkey := validatorSet[0].Validator.PublicKey

	beaconMock.PendingDepositsFunc = func(context.Context, *eth2api.PendingDepositsOpts) ([]*electra.PendingDeposit, error) {
		return []*electra.PendingDeposit{
			{Pubkey: noIndex[0]},   // cluster validator with a registered deposit but no index -> warn.
			{Pubkey: activePubkey}, // top-up for an already-indexed validator -> ignored.
		}, nil
	}

	var clusterPubkeys []eth2p0.BLSPubKey

	for pk := range shares {
		eth2PK, err := pk.ToETH2()
		require.NoError(t, err)

		clusterPubkeys = append(clusterPubkeys, eth2PK)
	}

	// index 0 is active_ongoing: its top-up deposit must be excluded from the warning.
	indexed := map[eth2p0.ValidatorIndex]*eth2v1.Validator{0: validatorSet[0]}

	got := warnOnPendingDeposits(ctx, beaconMock, clusterPubkeys, indexed)
	require.Equal(t, []eth2p0.BLSPubKey{noIndex[0]}, got)
}

func Test_signAllValidatorsExits_pendingDepositsCheckIsBestEffort(t *testing.T) {
	ctx := t.Context()

	shares, validatorSet, _ := mixedValidatorSet(t)

	beaconMock, err := beaconmock.New(ctx, beaconmock.WithValidatorSet(validatorSet))
	require.NoError(t, err)

	t.Cleanup(func() { require.NoError(t, beaconMock.Close()) })

	beaconMock.ValidatorsFunc = stateFilteringValidators(validatorSet)

	// A beacon node that does not support the pending-deposits queue (e.g. pre-Electra) must not
	// block signing exits for the exitable validators.
	beaconMock.PendingDepositsFunc = func(context.Context, *eth2api.PendingDepositsOpts) ([]*electra.PendingDeposit, error) {
		return nil, errors.New("pending deposits not supported")
	}

	config := exitConfig{ExitEpoch: 194048}

	exitBlobs, err := signAllValidatorsExits(ctx, config, beaconMock, shares)
	require.NoError(t, err)
	require.Len(t, exitBlobs, 2)
}
