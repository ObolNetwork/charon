// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"encoding/hex"
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
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil/obolapimock"
)

func TestDepositFetchValid(t *testing.T) {
	for _, compounding := range []bool{false, true} {
		t.Run(fmt.Sprintf("compounding=%v", compounding), func(t *testing.T) {
			testDepositFetchValid(t, compounding)
		})
	}
}

func testDepositFetchValid(t *testing.T, compounding bool) {
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
		func(d *cluster.Definition) { d.Compounding = compounding },
	)

	// Withdrawal credentials prefix, 0x02 for compounding clusters.
	prefix := "01"
	if compounding {
		prefix = "02"
	}

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
	defer srv.Close()

	addLockFiles(lock)

	// First submit partial deposits to API.
	for idx := range operatorAmt {
		baseDir := filepath.Join(root, fmt.Sprintf("op%d", idx))

		config := depositConfig{
			ValidatorPublicKeys: []string{lock.Validators[0].PublicKeyHex(), lock.Validators[1].PublicKeyHex()},
			PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
			ValidatorKeysDir:    filepath.Join(baseDir, "validator_keys"),
			LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
			PublishAddress:      srv.URL,
			PublishTimeout:      10 * time.Second,
		}

		signConfig := depositSignConfig{
			depositConfig: config,
			// One plain (checksummed) address and one full withdrawal credential.
			WithdrawalAddresses: []string{"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0x" + prefix + "00000000000000000000000000000000000000000000000000000000001235"},
			DepositAmounts:      []uint{32, 1},
		}

		require.NoError(t, runDepositSign(ctx, signConfig), "operator index submit deposit sign: %v", idx)
	}

	baseDir := filepath.Join(root, fmt.Sprintf("op%d", 0))

	config := depositConfig{
		ValidatorPublicKeys: []string{lock.Validators[0].PublicKeyHex(), lock.Validators[1].PublicKeyHex()},
		PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
		ValidatorKeysDir:    filepath.Join(baseDir, "validator_keys"),
		LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
		PublishAddress:      srv.URL,
		PublishTimeout:      10 * time.Second,
	}

	fetchConfig := depositFetchConfig{
		depositConfig:  config,
		DepositDataDir: filepath.Join(baseDir, "deposit_data"),
	}

	err = runDepositFetch(ctx, fetchConfig)
	require.NoError(t, err)

	depositDatas, err := deposit.ReadDepositDataFiles(fetchConfig.DepositDataDir)
	require.NoError(t, err)
	require.Len(t, depositDatas, 2)

	expectedCreds := map[string]string{
		lock.Validators[0].PublicKeyHex(): prefix + "00000000000000000000005aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
		lock.Validators[1].PublicKeyHex(): prefix + "00000000000000000000000000000000000000000000000000000000001235",
	}

	for _, dds := range depositDatas {
		require.Len(t, dds, 2)

		for _, dd := range dds {
			require.Equal(t, expectedCreds[dd.PublicKey.String()], hex.EncodeToString(dd.WithdrawalCredentials))
		}
	}
}

func TestDepositFetchCLI(t *testing.T) {
	tests := []struct {
		name        string
		expectedErr string

		flags []string
	}{
		{
			name:        "correct flags",
			expectedErr: "read cluster-lock.json: open test: no such file or directory",
			flags: []string{
				"--validator-public-keys=test",
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
			cmd := newDepositCmd(newDepositFetchCmd(runDepositFetch))
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
