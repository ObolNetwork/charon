// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil/obolapimock"
)

func TestDepositSignValid(t *testing.T) {
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

	lockJSON, err := json.Marshal(lock)
	require.NoError(t, err)

	writeAllLockData(t, root, enrs, operatorShares, lockJSON)

	handler, addLockFiles := obolapimock.MockServer(false, nil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	addLockFiles(lock)

	idx := 0

	baseDir := filepath.Join(root, fmt.Sprintf("op%d", idx))

	config := depositConfig{
		ValidatorPublicKeys: []string{lock.Validators[0].PublicKeyHex()},
		PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
		ValidatorKeysDir:    filepath.Join(baseDir, "validator_keys"),
		LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
		PublishAddress:      srv.URL,
		PublishTimeout:      10 * time.Second,
	}

	signConfig := depositSignConfig{
		depositConfig:       config,
		WithdrawalAddresses: []string{"0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"},
		DepositAmounts:      []uint{32},
	}

	require.NoError(t, runDepositSign(ctx, signConfig), "operator index submit deposit sign: %v", idx)
}

func TestDepositSignWithdrawalAddresses(t *testing.T) {
	const zeroAddr = "0x0000000000000000000000000000000000000000"

	tests := []struct {
		name        string
		mainnet     bool
		compounding bool
		addr        string
		expectedErr string
	}{
		{name: "mainnet zero address", mainnet: true, addr: zeroAddr, expectedErr: "zero withdrawal address forbidden"},
		{name: "mainnet zero credentials", mainnet: true, addr: "0x01" + strings.Repeat("00", 31), expectedErr: "zero withdrawal address forbidden"},
		{name: "mainnet address", mainnet: true, addr: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
		{name: "testnet zero address", addr: zeroAddr},
		{name: "compounding address", compounding: true, addr: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
		{name: "compounding 0x02 credentials", compounding: true, addr: "0x02" + strings.Repeat("00", 11) + "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"},
		{name: "compounding 0x01 credentials", compounding: true, addr: "0x01" + strings.Repeat("00", 11) + "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", expectedErr: "prefix does not match"},
		{name: "bad checksum", addr: "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", expectedErr: "does not match its EIP-55 checksum"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := log.WithCtx(t.Context(), z.Str("test_case", t.Name()))

			const operatorAmt = 4

			lock, enrs, keyShares := cluster.NewForT(t, 1, operatorAmt, operatorAmt, 0, rand.New(rand.NewSource(0)), func(d *cluster.Definition) {
				d.Compounding = test.compounding
				if test.mainnet {
					forkVersion, err := eth2util.NetworkToForkVersionBytes(eth2util.Mainnet.Name)
					require.NoError(t, err)

					d.ForkVersion = forkVersion
				}
			})

			operatorShares := make([][]tbls.PrivateKey, operatorAmt)
			for opIdx := range operatorAmt {
				operatorShares[opIdx] = append(operatorShares[opIdx], keyShares[0][opIdx])
			}

			lockJSON, err := json.Marshal(lock)
			require.NoError(t, err)

			root := t.TempDir()
			writeAllLockData(t, root, enrs, operatorShares, lockJSON)

			handler, addLockFiles := obolapimock.MockServer(false, nil)

			srv := httptest.NewServer(handler)
			defer srv.Close()

			addLockFiles(lock)

			baseDir := filepath.Join(root, "op0")
			signConfig := depositSignConfig{
				ValidatorPublicKeys: []string{lock.Validators[0].PublicKeyHex()},
				PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
				ValidatorKeysDir:    filepath.Join(baseDir, "validator_keys"),
				LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
				PublishAddress:      srv.URL,
				PublishTimeout:      10 * time.Second,
				WithdrawalAddresses: []string{test.addr},
				DepositAmounts:      []uint{32},
			}

			err = runDepositSign(ctx, signConfig)
			if test.expectedErr != "" {
				require.ErrorContains(t, err, test.expectedErr)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestDepositSignCLI(t *testing.T) {
	tests := []struct {
		name        string
		expectedErr string

		flags []string
	}{
		{
			name:        "correct flags",
			expectedErr: "load identity key: read private key from disk: open test: no such file or directory",
			flags: []string{
				"--validator-public-keys=test",
				"--withdrawal-addresses=test",
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
				"--withdrawal-addresses=test",
				"--private-key-file=test",
				"--validator-keys-dir=test",
				"--lock-file=test",
				"--publish-address=test",
				"--publish-timeout=1ms",
			},
		},
		{
			name:        "missing withdrawal addresses",
			expectedErr: "required flag(s) \"withdrawal-addresses\" not set",
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
			cmd := newDepositCmd(newDepositSignCmd(runDepositSign))
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
