// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http/httptest"
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

func TestFeeRecipientSignValid(t *testing.T) {
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

	idx := 0

	baseDir := filepath.Join(root, fmt.Sprintf("op%d", idx))

	config := feerecipientConfig{
		ValidatorPublicKeys: []string{lock.Validators[0].PublicKeyHex()},
		PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
		ValidatorKeysDir:    filepath.Join(baseDir, "validator_keys"),
		LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
		PublishAddress:      srv.URL,
		PublishTimeout:      10 * time.Second,
	}

	signConfig := feerecipientSignConfig{
		feerecipientConfig: config,
		FeeRecipient:       "0x0000000000000000000000000000000000001234",
	}

	require.NoError(t, runFeeRecipientSign(ctx, signConfig), "operator index submit feerecipient sign: %v", idx)
}

func TestFeeRecipientSignCLI(t *testing.T) {
	tests := []struct {
		name        string
		expectedErr string
		flags       []string
	}{
		{
			name:        "correct flags",
			expectedErr: "load identity key: read private key from disk: open test: no such file or directory",
			flags: []string{
				"--validator-public-keys=test",
				"--fee-recipient=0x0000000000000000000000000000000000001234",
				"--private-key-file=test",
				"--validator-keys-dir=test",
				"--lock-file=test",
				"--publish-address=test",
				"--publish-timeout=1ms",
			},
		},
		{
			name:        "missing validator public keys",
			expectedErr: "required flag(s) \"validator-public-keys\" not set",
			flags: []string{
				"--fee-recipient=0x0000000000000000000000000000000000001234",
				"--private-key-file=test",
				"--validator-keys-dir=test",
				"--lock-file=test",
				"--publish-address=test",
				"--publish-timeout=1ms",
			},
		},
		{
			name:        "missing fee recipient",
			expectedErr: "required flag(s) \"fee-recipient\" not set",
			flags: []string{
				"--validator-public-keys=test",
				"--private-key-file=test",
				"--validator-keys-dir=test",
				"--lock-file=test",
				"--publish-address=test",
				"--publish-timeout=1ms",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := newFeeRecipientCmd(newFeeRecipientSignCmd(runFeeRecipientSign))
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
