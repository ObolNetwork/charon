// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
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

func TestFeeRecipientFetchMergesWithExistingOverrides(t *testing.T) {
	ctx := t.Context()
	ctx = log.WithCtx(ctx, z.Str("test_case", t.Name()))

	valAmt := 2
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

	overridesFile := filepath.Join(root, "output", "builder_registrations_overrides.json")
	validatorAPubkey := lock.Validators[0].PublicKeyHex()
	validatorBPubkey := lock.Validators[1].PublicKeyHex()

	signThreshold := func(validatorPubkey string, feeRecipient string) {
		t.Helper()

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
				FeeRecipient:     feeRecipient,
			}

			require.NoError(t, runFeeRecipientSign(ctx, signConfig), "operator %d submit feerecipient sign", opIdx)
		}
	}

	fetch := func(validatorPubkey string) {
		t.Helper()

		fetchConfig := feerecipientFetchConfig{
			feerecipientConfig: feerecipientConfig{
				ValidatorPublicKeys: []string{validatorPubkey},
				LockFilePath:        filepath.Join(root, "op0", "cluster-lock.json"),
				OverridesFilePath:   overridesFile,
				PublishAddress:      srv.URL,
				PublishTimeout:      10 * time.Second,
			},
		}

		require.NoError(t, runFeeRecipientFetch(ctx, fetchConfig))
	}

	signThreshold(validatorAPubkey, "0x0000000000000000000000000000000000001234")
	fetch(validatorAPubkey)

	signThreshold(validatorBPubkey, "0x0000000000000000000000000000000000005678")
	fetch(validatorBPubkey)

	data, err := os.ReadFile(overridesFile)
	require.NoError(t, err)

	var regs []*eth2api.VersionedSignedValidatorRegistration
	require.NoError(t, json.Unmarshal(data, &regs))
	require.Len(t, regs, 2)

	byPubkey := make(map[string]string, len(regs))
	for _, reg := range regs {
		require.NotNil(t, reg)
		require.NotNil(t, reg.V1)
		require.NotNil(t, reg.V1.Message)

		pubkey := "0x" + strings.ToLower(hex.EncodeToString(reg.V1.Message.Pubkey[:]))
		byPubkey[pubkey] = reg.V1.Message.FeeRecipient.String()
	}

	require.Equal(t, "0x0000000000000000000000000000000000001234", strings.ToLower(byPubkey[strings.ToLower(validatorAPubkey)]))
	require.Equal(t, "0x0000000000000000000000000000000000005678", strings.ToLower(byPubkey[strings.ToLower(validatorBPubkey)]))
}

// TestFeeRecipientFetchSkipsInvalidSignature verifies that mergeFetchedValidatorRegistrations
// skips a registration with an invalid signature and still merges the remaining, valid ones,
// rather than aborting the whole batch.
func TestFeeRecipientFetchSkipsInvalidSignature(t *testing.T) {
	ctx := t.Context()
	ctx = log.WithCtx(ctx, z.Str("test_case", t.Name()))

	valAmt := 2
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

	validatorAPubkey := lock.Validators[0].PublicKeyHex()
	validatorBPubkey := lock.Validators[1].PublicKeyHex()

	signThreshold := func(validatorPubkey string, feeRecipient string) {
		t.Helper()

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
				FeeRecipient:     feeRecipient,
			}

			require.NoError(t, runFeeRecipientSign(ctx, signConfig), "operator %d submit feerecipient sign", opIdx)
		}
	}

	signThreshold(validatorAPubkey, "0x0000000000000000000000000000000000001234")
	signThreshold(validatorBPubkey, "0x0000000000000000000000000000000000005678")

	// Fetch each validator into its own file so we can extract the individually-signed,
	// fully aggregated registrations before feeding them into mergeFetchedValidatorRegistrations directly.
	fetchInto := func(validatorPubkey, path string) *eth2api.VersionedSignedValidatorRegistration {
		t.Helper()

		fetchConfig := feerecipientFetchConfig{
			feerecipientConfig: feerecipientConfig{
				ValidatorPublicKeys: []string{validatorPubkey},
				LockFilePath:        filepath.Join(root, "op0", "cluster-lock.json"),
				OverridesFilePath:   path,
				PublishAddress:      srv.URL,
				PublishTimeout:      10 * time.Second,
			},
		}

		require.NoError(t, runFeeRecipientFetch(ctx, fetchConfig))

		regs, err := app.LoadBuilderRegistrationOverrides(path, eth2p0.Version(lock.ForkVersion))
		require.NoError(t, err)
		require.Len(t, regs, 1)

		return regs[0]
	}

	regA := fetchInto(validatorAPubkey, filepath.Join(root, "output-a", "overrides.json"))
	regB := fetchInto(validatorBPubkey, filepath.Join(root, "output-b", "overrides.json"))

	// Corrupt validator B's signature to simulate a tampered/invalid fetched registration.
	regB.V1.Signature[0] ^= 0xff

	targetFile := filepath.Join(root, "output", "builder_registrations_overrides.json")

	merged, err := mergeFetchedValidatorRegistrations(ctx, targetFile, lock.ForkVersion, []*eth2api.VersionedSignedValidatorRegistration{regA, regB})
	require.NoError(t, err)
	require.Len(t, merged, 1, "invalid registration must be skipped, valid one must still be merged")
	require.Equal(t, strings.ToLower(validatorAPubkey), "0x"+strings.ToLower(hex.EncodeToString(merged[0].V1.Message.Pubkey[:])))

	// If every fetched registration is invalid, the existing overrides file's entry for
	// validator A must be preserved untouched rather than being wiped out or erroring.
	require.NoError(t, writeSignedValidatorRegistrations(targetFile, merged))

	mergedAfterAllInvalid, err := mergeFetchedValidatorRegistrations(ctx, targetFile, lock.ForkVersion, []*eth2api.VersionedSignedValidatorRegistration{regB})
	require.NoError(t, err)
	require.Len(t, mergedAfterAllInvalid, 1, "existing valid override must survive a batch that is entirely invalid")
	require.Equal(t, strings.ToLower(validatorAPubkey), "0x"+strings.ToLower(hex.EncodeToString(mergedAfterAllInvalid[0].V1.Message.Pubkey[:])))
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
