// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

func TestDepositFetchValid(t *testing.T) {
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

	writeAllLockData(t, root, operatorAmt, enrs, operatorShares, lockJSON)

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
			depositConfig:       config,
			WithdrawalAddresses: []string{"0x0100000000000000000000000000000000000000000000000000000000001234", "0x0100000000000000000000000000000000000000000000000000000000001235"},
			DepositAmounts:      []int{32, 1},
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
}
