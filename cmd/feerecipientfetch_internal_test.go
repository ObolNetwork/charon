// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil/obolapimock"
)

func TestFeeRecipientFetchValid(t *testing.T) {
	ctx := t.Context()
	ctx = log.WithCtx(ctx, z.Str("test_case", t.Name()))

	valAmt := 4
	operatorAmt := 4

	random := rand.New(rand.NewSource(0))

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

	lockJSON, err := json.Marshal(lock)
	require.NoError(t, err)

	writeAllLockData(t, root, operatorAmt, enrs, operatorShares, lockJSON)

	handler, addLockFiles := obolapimock.MockServer(false, nil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	addLockFiles(lock)

	// First, submit partial signatures from threshold operators.
	newFeeRecipient := "0x0000000000000000000000000000000000001234"
	validatorPubkey := lock.Validators[0].PublicKeyHex()

	for opIdx := range lock.Threshold {
		baseDir := filepath.Join(root, fmt.Sprintf("op%d", opIdx))

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

		require.NoError(t, runFeeRecipientSign(ctx, signConfig), "operator %d submit feerecipient sign", opIdx)
	}

	// Now fetch the aggregated registrations.
	overridesFile := filepath.Join(root, "output", "builder_registrations_overrides.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(overridesFile), 0o755))

	fetchConfig := feerecipientFetchConfig{
		feerecipientConfig: feerecipientConfig{
			LockFilePath:      filepath.Join(root, "op0", "cluster-lock.json"),
			OverridesFilePath: overridesFile,
			PublishAddress:    srv.URL,
			PublishTimeout:    10 * time.Second,
		},
	}

	require.NoError(t, runFeeRecipientFetch(ctx, fetchConfig))

	// Verify output file exists and contains registrations.
	data, err := os.ReadFile(overridesFile)
	require.NoError(t, err)
	require.NotEmpty(t, data)
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

	writeAllLockData(t, root, operatorAmt, enrs, operatorShares, lockJSON)

	// Start and immediately close the server so the URL is unreachable.
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()

	config := feerecipientFetchConfig{
		feerecipientConfig: feerecipientConfig{
			LockFilePath:   filepath.Join(root, "op0", "cluster-lock.json"),
			PublishAddress: srv.URL,
			PublishTimeout: time.Second,
		},
	}

	err = runFeeRecipientFetch(ctx, config)
	require.ErrorContains(t, err, "fetch builder registrations from Obol API")
}

func TestFeeRecipientFetchNoQuorum(t *testing.T) {
	ctx := t.Context()
	ctx = log.WithCtx(ctx, z.Str("test_case", t.Name()))

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

	writeAllLockData(t, root, operatorAmt, enrs, operatorShares, lockJSON)

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
