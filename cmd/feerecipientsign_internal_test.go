// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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

	writeAllLockData(t, root, enrs, operatorShares, lockJSON)

	handler, addLockFiles := obolapimock.MockServer(false, nil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	addLockFiles(lock)

	idx := 0

	baseDir := filepath.Join(root, fmt.Sprintf("op%d", idx))

	signConfig := feerecipientSignConfig{
		feerecipientConfig: feerecipientConfig{
			ValidatorPublicKeys: []string{lock.Validators[0].PublicKeyHex()},
			PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
			LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
			PublishAddress:      srv.URL,
			PublishTimeout:      10 * time.Second,
		},
		ValidatorKeysDir: filepath.Join(baseDir, "validator_keys"),
		FeeRecipient:     "0x0000000000000000000000000000000000001234",
	}

	require.NoError(t, runFeeRecipientSign(ctx, signConfig), "operator index submit feerecipient sign: %v", idx)
}

func TestFeeRecipientSignWithTimestamp(t *testing.T) {
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

	writeAllLockData(t, root, enrs, operatorShares, lockJSON)

	handler, addLockFiles := obolapimock.MockServer(false, nil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	addLockFiles(lock)

	// All operators sign independently with the same fixed timestamp.
	newFeeRecipient := "0x0000000000000000000000000000000000001234"
	validatorPubkey := lock.Validators[0].PublicKeyHex()
	fixedTimestamp := int64(1700000000)

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
			Timestamp:        fixedTimestamp,
		}

		require.NoError(t, runFeeRecipientSign(ctx, signConfig), "operator %d sign with timestamp", opIdx)
	}
}

func TestFeeRecipientSignInvalidFeeRecipient(t *testing.T) {
	config := feerecipientSignConfig{
		feerecipientConfig: feerecipientConfig{
			PrivateKeyPath: "nonexistent",
			LockFilePath:   "nonexistent",
			PublishAddress: "http://localhost:0",
			PublishTimeout: time.Second,
		},
		FeeRecipient: "not-an-address",
	}

	err := runFeeRecipientSign(t.Context(), config)
	require.ErrorContains(t, err, "invalid fee recipient address")
}

func TestValidateFeeRecipient(t *testing.T) {
	// EIP-55 test vector address.
	const checksummed = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"

	tests := []struct {
		name        string
		address     string
		expectedErr string
	}{
		{
			name:    "valid lowercase",
			address: strings.ToLower(checksummed),
		},
		{
			name:    "valid checksummed",
			address: checksummed,
		},
		{
			name:        "invalid checksum",
			address:     "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
			expectedErr: "does not match its EIP-55 checksum",
		},
		{
			name:        "zero address",
			address:     "0x0000000000000000000000000000000000000000",
			expectedErr: "must not be the zero address",
		},
		{
			name:        "not an address",
			address:     "not-an-address",
			expectedErr: "invalid fee recipient address",
		},
		{
			name:        "too short",
			address:     "0x1234",
			expectedErr: "invalid fee recipient address",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateFeeRecipient(test.address)
			if test.expectedErr != "" {
				require.ErrorContains(t, err, test.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestFeeRecipientSignStaleTimestampRejected verifies that signing a new fee recipient with a
// timestamp that is not later than the current quorum registration is rejected, since the
// resulting registration would never be applied.
func TestFeeRecipientSignStaleTimestampRejected(t *testing.T) {
	ctx := log.WithCtx(t.Context(), z.Str("test_case", t.Name()))

	c := setupFeeRecipientTestCluster(t, 1)
	validatorPubkey := c.lock.Validators[0].PublicKeyHex()

	ts1 := time.Now().Add(time.Hour).Unix()

	signFeeRecipientThreshold(ctx, t, c, validatorPubkey, "0x0000000000000000000000000000000000001234", ts1)

	signConfig := signConfigForOperator(c, 0, validatorPubkey, "0x0000000000000000000000000000000000005678", ts1)
	err := runFeeRecipientSign(ctx, signConfig)
	require.ErrorContains(t, err, "timestamp must be later than the current registration with quorum")
}

// TestFeeRecipientSignAdoptsInProgressTimestamp verifies that operators joining an in-progress
// registration adopt its timestamp even when they pass a conflicting --timestamp, so partial
// signatures aggregate to quorum.
func TestFeeRecipientSignAdoptsInProgressTimestamp(t *testing.T) {
	ctx := log.WithCtx(t.Context(), z.Str("test_case", t.Name()))

	c := setupFeeRecipientTestCluster(t, 1)
	validatorPubkey := c.lock.Validators[0].PublicKeyHex()
	newFeeRecipient := "0x0000000000000000000000000000000000001234"

	ts1 := time.Now().Add(time.Hour).Unix()
	ts2 := time.Now().Add(2 * time.Hour).Unix()

	// The first operator anchors the in-progress registration at ts1.
	require.NoError(t, runFeeRecipientSign(ctx, signConfigForOperator(c, 0, validatorPubkey, newFeeRecipient, ts1)))

	// The remaining operators pass a different explicit timestamp, which is ignored in
	// favor of the in-progress registration's timestamp.
	for opIdx := 1; opIdx < c.lock.Threshold; opIdx++ {
		require.NoError(t, runFeeRecipientSign(ctx, signConfigForOperator(c, opIdx, validatorPubkey, newFeeRecipient, ts2)))
	}

	overridesFile := filepath.Join(c.root, "output", "builder_registrations_overrides.json")
	fetchFeeRecipient(ctx, t, c, nil, overridesFile)

	regs, byPubkey := readOverridesFile(t, overridesFile)
	require.Len(t, regs, 1, "partial signatures must aggregate to quorum despite conflicting --timestamp flags")
	require.Equal(t, newFeeRecipient, byPubkey[strings.ToLower(validatorPubkey)])
	require.Equal(t, ts1, regs[0].V1.Message.Timestamp.Unix())
}

func TestFeeRecipientSignInvalidLockFile(t *testing.T) {
	config := feerecipientSignConfig{
		feerecipientConfig: feerecipientConfig{
			PrivateKeyPath: "nonexistent",
			LockFilePath:   "nonexistent-lock.json",
			PublishAddress: "http://localhost:0",
			PublishTimeout: time.Second,
		},
		FeeRecipient: "0x0000000000000000000000000000000000001234",
	}

	err := runFeeRecipientSign(t.Context(), config)
	require.ErrorContains(t, err, "read private key from disk")
}

func TestFeeRecipientSignAPIUnreachable(t *testing.T) {
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

	writeAllLockData(t, root, enrs, operatorShares, lockJSON)

	// Start and immediately close the server so the URL is unreachable.
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()

	baseDir := filepath.Join(root, "op0")

	config := feerecipientSignConfig{
		feerecipientConfig: feerecipientConfig{
			ValidatorPublicKeys: []string{lock.Validators[0].PublicKeyHex()},
			PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
			LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
			PublishAddress:      srv.URL,
			PublishTimeout:      time.Second,
		},
		ValidatorKeysDir: filepath.Join(baseDir, "validator_keys"),
		FeeRecipient:     "0x0000000000000000000000000000000000001234",
	}

	err = runFeeRecipientSign(ctx, config)
	require.ErrorContains(t, err, "fetch builder registration status from Obol API")
}

func TestFeeRecipientSignPubkeyNotInCluster(t *testing.T) {
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

	writeAllLockData(t, root, enrs, operatorShares, lockJSON)

	handler, addLockFiles := obolapimock.MockServer(false, nil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	addLockFiles(lock)

	baseDir := filepath.Join(root, "op0")

	config := feerecipientSignConfig{
		feerecipientConfig: feerecipientConfig{
			ValidatorPublicKeys: []string{"0x" + strings.Repeat("ab", 48)},
			PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
			LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
			PublishAddress:      srv.URL,
			PublishTimeout:      10 * time.Second,
		},
		ValidatorKeysDir: filepath.Join(baseDir, "validator_keys"),
		FeeRecipient:     "0x0000000000000000000000000000000000001234",
	}

	err = runFeeRecipientSign(ctx, config)
	require.ErrorContains(t, err, "validator pubkey not found in cluster lock")
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
			name:        "correct flags with timestamp",
			expectedErr: "load identity key: read private key from disk: open test: no such file or directory",
			flags: []string{
				"--validator-public-keys=test",
				"--fee-recipient=0x0000000000000000000000000000000000001234",
				"--private-key-file=test",
				"--validator-keys-dir=test",
				"--lock-file=test",
				"--publish-address=test",
				"--publish-timeout=1ms",
				"--timestamp=1700000000",
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
