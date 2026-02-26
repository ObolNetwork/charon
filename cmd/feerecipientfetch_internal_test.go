// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"encoding/json"
	"fmt"
	"math/rand"
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
				ValidatorKeysDir:    filepath.Join(baseDir, "validator_keys"),
				LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
				PublishAddress:      srv.URL,
				PublishTimeout:      10 * time.Second,
			},
			FeeRecipient: newFeeRecipient,
		}

		require.NoError(t, runFeeRecipientSign(ctx, signConfig), "operator %d submit feerecipient sign", opIdx)
	}

	// Now fetch the aggregated registration.
	outputDir := filepath.Join(root, "builder_registrations")

	fetchConfig := feerecipientFetchConfig{
		feerecipientConfig: feerecipientConfig{
			ValidatorPublicKeys: []string{validatorPubkey},
			PrivateKeyPath:      filepath.Join(root, "op0", "charon-enr-private-key"),
			LockFilePath:        filepath.Join(root, "op0", "cluster-lock.json"),
			PublishAddress:      srv.URL,
			PublishTimeout:      10 * time.Second,
		},
		OutputDir: outputDir,
	}

	require.NoError(t, runFeeRecipientFetch(ctx, fetchConfig))

	// Verify output file exists.
	files, err := os.ReadDir(outputDir)
	require.NoError(t, err)
	require.Len(t, files, 1)
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
				"--output-dir=test",
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
