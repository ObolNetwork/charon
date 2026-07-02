// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil/obolapimock"
)

// feeRecipientTestCluster holds a test cluster with lock data written to disk and a
// mock Obol API server, shared by the feerecipient command tests.
type feeRecipientTestCluster struct {
	lock   cluster.Lock
	root   string
	srvURL string
}

func setupFeeRecipientTestCluster(t *testing.T, valAmt int) feeRecipientTestCluster {
	t.Helper()

	const operatorAmt = 4

	random := rand.New(rand.NewSource(0))

	lock, enrs, keyShares := cluster.NewForT(t, valAmt, operatorAmt, operatorAmt, 0, random)

	root := t.TempDir()

	operatorShares := make([][]tbls.PrivateKey, operatorAmt)
	for opIdx := range operatorAmt {
		for _, share := range keyShares {
			operatorShares[opIdx] = append(operatorShares[opIdx], share[opIdx])
		}
	}

	lockJSON, err := json.Marshal(lock)
	require.NoError(t, err)

	writeAllLockData(t, root, enrs, operatorShares, lockJSON)

	handler, addLockFiles := obolapimock.MockServer(false, nil)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	addLockFiles(lock)

	return feeRecipientTestCluster{lock: lock, root: root, srvURL: srv.URL}
}

// signConfigForOperator returns a sign config for the given operator index.
func signConfigForOperator(c feeRecipientTestCluster, opIdx int, validatorPubkey, feeRecipient string, timestamp int64) feerecipientSignConfig {
	baseDir := filepath.Join(c.root, fmt.Sprintf("op%d", opIdx))

	return feerecipientSignConfig{
		feerecipientConfig: feerecipientConfig{
			ValidatorPublicKeys: []string{validatorPubkey},
			PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
			LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
			PublishAddress:      c.srvURL,
			PublishTimeout:      10 * time.Second,
		},
		ValidatorKeysDir: filepath.Join(baseDir, "validator_keys"),
		FeeRecipient:     feeRecipient,
		Timestamp:        timestamp,
	}
}

// signFeeRecipientThreshold submits partial signatures from a threshold of operators.
func signFeeRecipientThreshold(ctx context.Context, t *testing.T, c feeRecipientTestCluster, validatorPubkey, feeRecipient string, timestamp int64) {
	t.Helper()

	for opIdx := range c.lock.Threshold {
		signConfig := signConfigForOperator(c, opIdx, validatorPubkey, feeRecipient, timestamp)
		require.NoError(t, runFeeRecipientSign(ctx, signConfig), "operator %d submit feerecipient sign", opIdx)
	}
}

// fetchFeeRecipient runs the fetch command for the given validators into overridesFile.
func fetchFeeRecipient(ctx context.Context, t *testing.T, c feeRecipientTestCluster, validatorPubkeys []string, overridesFile string) {
	t.Helper()

	fetchConfig := feerecipientFetchConfig{
		feerecipientConfig: feerecipientConfig{
			ValidatorPublicKeys: validatorPubkeys,
			LockFilePath:        filepath.Join(c.root, "op0", "cluster-lock.json"),
			OverridesFilePath:   overridesFile,
			PublishAddress:      c.srvURL,
			PublishTimeout:      10 * time.Second,
		},
	}

	require.NoError(t, runFeeRecipientFetch(ctx, fetchConfig))
}

// readOverridesFile reads and parses the overrides file, returning fee recipients keyed by
// 0x-prefixed lowercase validator pubkey hex.
func readOverridesFile(t *testing.T, path string) ([]*eth2api.VersionedSignedValidatorRegistration, map[string]string) {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var regs []*eth2api.VersionedSignedValidatorRegistration
	require.NoError(t, json.Unmarshal(data, &regs))

	byPubkey := make(map[string]string, len(regs))

	for _, reg := range regs {
		require.NotNil(t, reg)
		require.NotNil(t, reg.V1)
		require.NotNil(t, reg.V1.Message)

		pubkey := "0x" + hex.EncodeToString(reg.V1.Message.Pubkey[:])
		byPubkey[pubkey] = strings.ToLower(reg.V1.Message.FeeRecipient.String())
	}

	return regs, byPubkey
}

func TestFeeRecipientFetchValid(t *testing.T) {
	ctx := log.WithCtx(t.Context(), z.Str("test_case", t.Name()))

	c := setupFeeRecipientTestCluster(t, 4)

	newFeeRecipient := "0x0000000000000000000000000000000000001234"
	validatorPubkey := c.lock.Validators[0].PublicKeyHex()

	signFeeRecipientThreshold(ctx, t, c, validatorPubkey, newFeeRecipient, 0)

	overridesFile := filepath.Join(c.root, "output", "builder_registrations_overrides.json")
	fetchFeeRecipient(ctx, t, c, nil, overridesFile)

	regs, byPubkey := readOverridesFile(t, overridesFile)
	require.Len(t, regs, 1)
	require.Equal(t, newFeeRecipient, byPubkey[strings.ToLower(validatorPubkey)])
}

func TestFeeRecipientFetchMergesWithExistingOverrides(t *testing.T) {
	ctx := log.WithCtx(t.Context(), z.Str("test_case", t.Name()))

	c := setupFeeRecipientTestCluster(t, 2)

	overridesFile := filepath.Join(c.root, "output", "builder_registrations_overrides.json")
	validatorAPubkey := c.lock.Validators[0].PublicKeyHex()
	validatorBPubkey := c.lock.Validators[1].PublicKeyHex()

	signFeeRecipientThreshold(ctx, t, c, validatorAPubkey, "0x0000000000000000000000000000000000001234", 0)
	fetchFeeRecipient(ctx, t, c, []string{validatorAPubkey}, overridesFile)

	signFeeRecipientThreshold(ctx, t, c, validatorBPubkey, "0x0000000000000000000000000000000000005678", 0)
	fetchFeeRecipient(ctx, t, c, []string{validatorBPubkey}, overridesFile)

	regs, byPubkey := readOverridesFile(t, overridesFile)
	require.Len(t, regs, 2)
	require.Equal(t, "0x0000000000000000000000000000000000001234", byPubkey[strings.ToLower(validatorAPubkey)])
	require.Equal(t, "0x0000000000000000000000000000000000005678", byPubkey[strings.ToLower(validatorBPubkey)])
}

// TestFeeRecipientFetchUpdatesSameValidator verifies the core update flow: re-signing the
// same validator with a new fee recipient and a later timestamp replaces the on-disk entry.
func TestFeeRecipientFetchUpdatesSameValidator(t *testing.T) {
	ctx := log.WithCtx(t.Context(), z.Str("test_case", t.Name()))

	c := setupFeeRecipientTestCluster(t, 1)

	overridesFile := filepath.Join(c.root, "output", "builder_registrations_overrides.json")
	validatorPubkey := c.lock.Validators[0].PublicKeyHex()

	ts1 := time.Now().Add(time.Hour).Unix()
	ts2 := time.Now().Add(2 * time.Hour).Unix()

	signFeeRecipientThreshold(ctx, t, c, validatorPubkey, "0x0000000000000000000000000000000000001234", ts1)
	fetchFeeRecipient(ctx, t, c, nil, overridesFile)

	regs, byPubkey := readOverridesFile(t, overridesFile)
	require.Len(t, regs, 1)
	require.Equal(t, "0x0000000000000000000000000000000000001234", byPubkey[strings.ToLower(validatorPubkey)])

	signFeeRecipientThreshold(ctx, t, c, validatorPubkey, "0x0000000000000000000000000000000000005678", ts2)
	fetchFeeRecipient(ctx, t, c, nil, overridesFile)

	regs, byPubkey = readOverridesFile(t, overridesFile)
	require.Len(t, regs, 1)
	require.Equal(t, "0x0000000000000000000000000000000000005678", byPubkey[strings.ToLower(validatorPubkey)])
	require.Equal(t, ts2, regs[0].V1.Message.Timestamp.Unix())

	// A repeated fetch of the same data must be idempotent.
	fetchFeeRecipient(ctx, t, c, nil, overridesFile)

	regs, byPubkey = readOverridesFile(t, overridesFile)
	require.Len(t, regs, 1)
	require.Equal(t, "0x0000000000000000000000000000000000005678", byPubkey[strings.ToLower(validatorPubkey)])
}

// TestFeeRecipientFetchSelfHealsCorruptOverrides verifies that a corrupt overrides file does
// not block fetching: the file is rebuilt from the fetched registrations.
func TestFeeRecipientFetchSelfHealsCorruptOverrides(t *testing.T) {
	ctx := log.WithCtx(t.Context(), z.Str("test_case", t.Name()))

	c := setupFeeRecipientTestCluster(t, 1)

	overridesFile := filepath.Join(c.root, "output", "builder_registrations_overrides.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(overridesFile), 0o755))
	require.NoError(t, os.WriteFile(overridesFile, []byte("{corrupt"), 0o644))

	newFeeRecipient := "0x0000000000000000000000000000000000001234"
	validatorPubkey := c.lock.Validators[0].PublicKeyHex()

	signFeeRecipientThreshold(ctx, t, c, validatorPubkey, newFeeRecipient, 0)
	fetchFeeRecipient(ctx, t, c, nil, overridesFile)

	regs, byPubkey := readOverridesFile(t, overridesFile)
	require.Len(t, regs, 1)
	require.Equal(t, newFeeRecipient, byPubkey[strings.ToLower(validatorPubkey)])
}

// TestFeeRecipientFetchSkipsInvalidSignature verifies that merging skips a registration with
// an invalid signature and still merges the remaining, valid ones, rather than aborting the
// whole batch.
func TestFeeRecipientFetchSkipsInvalidSignature(t *testing.T) {
	ctx := log.WithCtx(t.Context(), z.Str("test_case", t.Name()))

	c := setupFeeRecipientTestCluster(t, 2)

	validatorAPubkey := c.lock.Validators[0].PublicKeyHex()
	validatorBPubkey := c.lock.Validators[1].PublicKeyHex()

	signFeeRecipientThreshold(ctx, t, c, validatorAPubkey, "0x0000000000000000000000000000000000001234", 0)
	signFeeRecipientThreshold(ctx, t, c, validatorBPubkey, "0x0000000000000000000000000000000000005678", 0)

	// Fetch each validator into its own file so we can extract the individually-signed,
	// fully aggregated registrations before feeding them into the merge directly.
	fetchInto := func(validatorPubkey, path string) *eth2api.VersionedSignedValidatorRegistration {
		t.Helper()

		fetchFeeRecipient(ctx, t, c, []string{validatorPubkey}, path)

		regs, err := app.LoadBuilderRegistrationOverrides(path, eth2p0.Version(c.lock.ForkVersion))
		require.NoError(t, err)
		require.Len(t, regs, 1)

		return regs[0]
	}

	regA := fetchInto(validatorAPubkey, filepath.Join(c.root, "output-a", "overrides.json"))
	regB := fetchInto(validatorBPubkey, filepath.Join(c.root, "output-b", "overrides.json"))

	// Corrupt validator B's signature to simulate a tampered/invalid fetched registration.
	regB.V1.Signature[0] ^= 0xff

	targetFile := filepath.Join(c.root, "output", "builder_registrations_overrides.json")

	merged := app.MergeBuilderRegistrationOverrides(ctx, targetFile, eth2p0.Version(c.lock.ForkVersion), []*eth2api.VersionedSignedValidatorRegistration{regA, regB})
	require.Len(t, merged, 1, "invalid registration must be skipped, valid one must still be merged")
	require.Equal(t, strings.ToLower(validatorAPubkey), "0x"+hex.EncodeToString(merged[0].V1.Message.Pubkey[:]))

	// If every fetched registration is invalid, the existing overrides file's entry for
	// validator A must be preserved untouched rather than being wiped out or erroring.
	require.NoError(t, writeSignedValidatorRegistrations(targetFile, merged))

	mergedAfterAllInvalid := app.MergeBuilderRegistrationOverrides(ctx, targetFile, eth2p0.Version(c.lock.ForkVersion), []*eth2api.VersionedSignedValidatorRegistration{regB})
	require.Len(t, mergedAfterAllInvalid, 1, "existing valid override must survive a batch that is entirely invalid")
	require.Equal(t, strings.ToLower(validatorAPubkey), "0x"+hex.EncodeToString(mergedAfterAllInvalid[0].V1.Message.Pubkey[:]))
}

func TestFeeRecipientFetchInvalidLockFile(t *testing.T) {
	config := feerecipientFetchConfig{
		feerecipientConfig: feerecipientConfig{
			LockFilePath:   "nonexistent-lock.json",
			PublishAddress: "http://localhost:0",
			PublishTimeout: time.Second,
		},
	}

	err := runFeeRecipientFetch(t.Context(), config)
	require.ErrorContains(t, err, "no such file or directory")
}

func TestFeeRecipientFetchAPIUnreachable(t *testing.T) {
	ctx := t.Context()

	c := setupFeeRecipientTestCluster(t, 1)

	// Start and immediately close a server so the URL is unreachable.
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()

	config := feerecipientFetchConfig{
		feerecipientConfig: feerecipientConfig{
			LockFilePath:   filepath.Join(c.root, "op0", "cluster-lock.json"),
			PublishAddress: srv.URL,
			PublishTimeout: time.Second,
		},
	}

	err := runFeeRecipientFetch(ctx, config)
	require.ErrorContains(t, err, "fetch builder registrations from Obol API")
}

func TestFeeRecipientFetchNoQuorum(t *testing.T) {
	ctx := log.WithCtx(t.Context(), z.Str("test_case", t.Name()))

	valAmt := 1
	operatorAmt := 4

	random := rand.New(rand.NewSource(0))

	lock, enrs, keyShares := cluster.NewForT(t, valAmt, operatorAmt, operatorAmt, 0, random)

	root := t.TempDir()

	operatorShares := make([][]tbls.PrivateKey, operatorAmt)
	for opIdx := range operatorAmt {
		for _, share := range keyShares {
			operatorShares[opIdx] = append(operatorShares[opIdx], share[opIdx])
		}
	}

	lockJSON, err := json.Marshal(lock)
	require.NoError(t, err)

	writeAllLockData(t, root, enrs, operatorShares, lockJSON)

	// dropOnePsig=true causes the mock to drop one partial, preventing quorum.
	handler, addLockFiles := obolapimock.MockServer(true, nil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	addLockFiles(lock)

	// Submit from only one operator (below threshold).
	newFeeRecipient := "0x0000000000000000000000000000000000001234"
	validatorPubkey := lock.Validators[0].PublicKeyHex()
	baseDir := filepath.Join(root, "op0")

	signConfig := feerecipientSignConfig{
		feerecipientConfig: feerecipientConfig{
			ValidatorPublicKeys: []string{validatorPubkey},
			PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
			LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
			PublishAddress:      srv.URL,
			PublishTimeout:      10 * time.Second,
		},
		ValidatorKeysDir: filepath.Join(baseDir, "validator_keys"),
		FeeRecipient:     newFeeRecipient,
	}

	require.NoError(t, runFeeRecipientSign(ctx, signConfig))

	// Fetch should succeed but produce no output file.
	overridesFile := filepath.Join(root, "output", "builder_registrations_overrides.json")

	fetchConfig := feerecipientFetchConfig{
		feerecipientConfig: feerecipientConfig{
			LockFilePath:      filepath.Join(root, "op0", "cluster-lock.json"),
			OverridesFilePath: overridesFile,
			PublishAddress:    srv.URL,
			PublishTimeout:    10 * time.Second,
		},
	}

	require.NoError(t, runFeeRecipientFetch(ctx, fetchConfig))

	// No quorum means no output file should be written.
	_, err = os.Stat(overridesFile)
	require.True(t, os.IsNotExist(err), "overrides file should not exist when no quorum")
}

func TestFeeRecipientFetchCLI(t *testing.T) {
	tests := []struct {
		name        string
		expectedErr string
		flags       []string
	}{
		{
			name:        "correct flags",
			expectedErr: "read cluster-lock.json: open test: no such file or directory",
			flags: []string{
				"--lock-file=test",
				"--publish-address=test",
				"--publish-timeout=1ms",
				"--overrides-file=test",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := newFeeRecipientCmd(newFeeRecipientFetchCmd(runFeeRecipientFetch))
			cmd.SetArgs(append([]string{"fetch"}, test.flags...))

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
