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
	"regexp"
	"strings"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/registration"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil/obolapimock"
)

func TestFeeRecipientListValid(t *testing.T) {
	valAmt := 4
	operatorAmt := 4

	random := rand.New(rand.NewSource(0))

	lock, _, _ := cluster.NewForT(t, valAmt, operatorAmt, operatorAmt, 0, random)

	lockJSON, err := json.Marshal(lock)
	require.NoError(t, err)

	lockFile := filepath.Join(t.TempDir(), "cluster-lock.json")
	require.NoError(t, os.WriteFile(lockFile, lockJSON, 0o644))

	config := feerecipientListConfig{
		feerecipientConfig: feerecipientConfig{
			LockFilePath:      lockFile,
			OverridesFilePath: filepath.Join(t.TempDir(), "nonexistent-overrides.json"),
			PublishAddress:    "http://127.0.0.1:0",
			PublishTimeout:    500 * time.Millisecond,
		},
	}

	require.NoError(t, runFeeRecipientList(t.Context(), config))
}

func TestFeeRecipientListWithFilter(t *testing.T) {
	valAmt := 4
	operatorAmt := 4

	random := rand.New(rand.NewSource(0))

	lock, _, _ := cluster.NewForT(t, valAmt, operatorAmt, operatorAmt, 0, random)

	lockJSON, err := json.Marshal(lock)
	require.NoError(t, err)

	lockFile := filepath.Join(t.TempDir(), "cluster-lock.json")
	require.NoError(t, os.WriteFile(lockFile, lockJSON, 0o644))

	config := feerecipientListConfig{
		feerecipientConfig: feerecipientConfig{
			ValidatorPublicKeys: []string{lock.Validators[0].PublicKeyHex()},
			LockFilePath:        lockFile,
			OverridesFilePath:   filepath.Join(t.TempDir(), "nonexistent-overrides.json"),
			PublishAddress:      "http://127.0.0.1:0",
			PublishTimeout:      500 * time.Millisecond,
		},
	}

	require.NoError(t, runFeeRecipientList(t.Context(), config))
}

func TestFeeRecipientListInvalidPubkey(t *testing.T) {
	valAmt := 1
	operatorAmt := 4

	random := rand.New(rand.NewSource(0))

	lock, _, _ := cluster.NewForT(t, valAmt, operatorAmt, operatorAmt, 0, random)

	lockJSON, err := json.Marshal(lock)
	require.NoError(t, err)

	lockFile := filepath.Join(t.TempDir(), "cluster-lock.json")
	require.NoError(t, os.WriteFile(lockFile, lockJSON, 0o644))

	config := feerecipientListConfig{
		feerecipientConfig: feerecipientConfig{
			ValidatorPublicKeys: []string{"0x" + strings.Repeat("ab", 48)},
			LockFilePath:        lockFile,
			OverridesFilePath:   filepath.Join(t.TempDir(), "nonexistent-overrides.json"),
		},
	}

	err = runFeeRecipientList(t.Context(), config)
	require.ErrorContains(t, err, "validator pubkey not found in cluster lock")
}

func TestFeeRecipientListInvalidLockFile(t *testing.T) {
	config := feerecipientListConfig{
		feerecipientConfig: feerecipientConfig{
			LockFilePath:      "nonexistent-lock.json",
			OverridesFilePath: filepath.Join(t.TempDir(), "nonexistent-overrides.json"),
		},
	}

	err := runFeeRecipientList(t.Context(), config)
	require.ErrorContains(t, err, "no such file or directory")
}

func TestFeeRecipientListWithOverrides(t *testing.T) {
	valAmt := 2
	operatorAmt := 4

	random := rand.New(rand.NewSource(0))

	lock, _, keyShares := cluster.NewForT(t, valAmt, operatorAmt, operatorAmt, 0, random)

	lockJSON, err := json.Marshal(lock)
	require.NoError(t, err)

	lockFile := filepath.Join(t.TempDir(), "cluster-lock.json")
	require.NoError(t, os.WriteFile(lockFile, lockJSON, 0o644))

	// Create a properly signed override with a newer timestamp for the first validator.
	override := makeSignedOverride(t, lock, keyShares, 0,
		bellatrix.ExecutionAddress{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x78},
		99999,
		time.Now().Add(time.Hour),
	)

	overridesJSON, err := json.Marshal([]*eth2api.VersionedSignedValidatorRegistration{override})
	require.NoError(t, err)

	overridesFile := filepath.Join(t.TempDir(), "overrides.json")
	require.NoError(t, os.WriteFile(overridesFile, overridesJSON, 0o644))

	config := feerecipientListConfig{
		feerecipientConfig: feerecipientConfig{
			LockFilePath:      lockFile,
			OverridesFilePath: overridesFile,
			PublishAddress:    "http://127.0.0.1:0",
			PublishTimeout:    500 * time.Millisecond,
		},
	}

	require.NoError(t, runFeeRecipientList(t.Context(), config))
}

// makeSignedOverride creates a properly signed builder registration override for the validator at valIdx.
func makeSignedOverride(
	t *testing.T,
	lock cluster.Lock,
	keyShares [][]tbls.PrivateKey,
	valIdx int,
	feeRecipient bellatrix.ExecutionAddress,
	gasLimit uint64,
	timestamp time.Time,
) *eth2api.VersionedSignedValidatorRegistration {
	t.Helper()

	// Reconstruct root secret from shares.
	sharesMap := make(map[int]tbls.PrivateKey)
	for i, share := range keyShares[valIdx] {
		sharesMap[i+1] = share
	}

	rootSecret, err := tbls.RecoverSecret(sharesMap, uint(len(keyShares[valIdx])), uint(lock.Threshold))
	require.NoError(t, err)

	pubkey, err := tblsconv.PubkeyToETH2(tbls.PublicKey(lock.Validators[valIdx].PubKey))
	require.NoError(t, err)

	msg := &eth2v1.ValidatorRegistration{
		FeeRecipient: feeRecipient,
		GasLimit:     gasLimit,
		Timestamp:    timestamp,
		Pubkey:       pubkey,
	}

	forkVersion, err := eth2util.NetworkToForkVersionBytes(eth2util.Goerli.Name)
	require.NoError(t, err)

	sigRoot, err := registration.GetMessageSigningRoot(msg, eth2p0.Version(forkVersion))
	require.NoError(t, err)

	sig, err := tbls.Sign(rootSecret, sigRoot[:])
	require.NoError(t, err)

	return &eth2api.VersionedSignedValidatorRegistration{
		Version: eth2spec.BuilderVersionV1,
		V1: &eth2v1.SignedValidatorRegistration{
			Message:   msg,
			Signature: eth2p0.BLSSignature(sig),
		},
	}
}

func TestResolveLatestRegistrations(t *testing.T) {
	valAmt := 2
	operatorAmt := 4

	random := rand.New(rand.NewSource(0))

	lock, _, _ := cluster.NewForT(t, valAmt, operatorAmt, operatorAmt, 0, random)

	lockTimestamp := lock.Validators[0].BuilderRegistration.Message.Timestamp
	normalizedPubkey := normalizePubkey(lock.Validators[0].PublicKeyHex())

	t.Run("no overrides", func(t *testing.T) {
		entries := resolveLatestRegistrations(lock, nil, nil, nil)
		require.Len(t, entries, 2)

		require.Equal(t, lock.Validators[0].PublicKeyHex(), entries[0].Pubkey)
		require.Equal(t, "0x"+hex.EncodeToString(lock.Validators[0].BuilderRegistration.Message.FeeRecipient), entries[0].FeeRecipient)
		require.Equal(t, uint64(lock.Validators[0].BuilderRegistration.Message.GasLimit), entries[0].GasLimit)
		require.Equal(t, []string{"lock"}, entries[0].Sources)
		require.Equal(t, []string{"lock"}, entries[1].Sources)
	})

	t.Run("override with newer timestamp wins", func(t *testing.T) {
		overrides := map[string]registrationEntry{
			normalizedPubkey: {
				FeeRecipient: "0x0000000000000000000000000000000000005678",
				GasLimit:     99999,
				Timestamp:    lockTimestamp.Add(time.Hour),
			},
		}

		entries := resolveLatestRegistrations(lock, overrides, nil, nil)
		require.Len(t, entries, 2)

		require.Equal(t, "0x0000000000000000000000000000000000005678", entries[0].FeeRecipient)
		require.Equal(t, uint64(99999), entries[0].GasLimit)
		require.Equal(t, []string{"overrides"}, entries[0].Sources)
		require.Equal(t, []string{"lock"}, entries[1].Sources)
	})

	t.Run("override with older timestamp loses", func(t *testing.T) {
		overrides := map[string]registrationEntry{
			normalizedPubkey: {
				FeeRecipient: "0x0000000000000000000000000000000000005678",
				GasLimit:     99999,
				Timestamp:    lockTimestamp.Add(-time.Hour),
			},
		}

		entries := resolveLatestRegistrations(lock, overrides, nil, nil)
		require.Len(t, entries, 2)

		// Should keep lock values.
		require.Equal(t, "0x"+hex.EncodeToString(lock.Validators[0].BuilderRegistration.Message.FeeRecipient), entries[0].FeeRecipient)
		require.Equal(t, uint64(lock.Validators[0].BuilderRegistration.Message.GasLimit), entries[0].GasLimit)
		require.Equal(t, []string{"lock"}, entries[0].Sources)
		require.Equal(t, []string{"lock"}, entries[1].Sources)
	})

	t.Run("pubkey filter", func(t *testing.T) {
		filter := map[string]struct{}{
			normalizedPubkey: {},
		}

		entries := resolveLatestRegistrations(lock, nil, nil, filter)
		require.Len(t, entries, 1)
		require.Equal(t, lock.Validators[0].PublicKeyHex(), entries[0].Pubkey)
		require.Equal(t, []string{"lock"}, entries[0].Sources)
	})

	t.Run("remote only, newer than lock, no override", func(t *testing.T) {
		remote := map[string]registrationEntry{
			normalizedPubkey: {
				FeeRecipient: "0x000000000000000000000000000000000000aaaa",
				GasLimit:     11111,
				Timestamp:    lockTimestamp.Add(time.Hour),
			},
		}

		entries := resolveLatestRegistrations(lock, nil, remote, nil)
		require.Len(t, entries, 2)

		require.Equal(t, "0x000000000000000000000000000000000000aaaa", entries[0].FeeRecipient)
		require.Equal(t, uint64(11111), entries[0].GasLimit)
		require.Equal(t, []string{"remote"}, entries[0].Sources)
		require.Equal(t, []string{"lock"}, entries[1].Sources)
	})

	t.Run("override and remote equivalent, both newer than lock", func(t *testing.T) {
		equalTS := lockTimestamp.Add(time.Hour)
		overrides := map[string]registrationEntry{
			normalizedPubkey: {
				FeeRecipient: "0x000000000000000000000000000000000000bbbb",
				GasLimit:     22222,
				Timestamp:    equalTS,
			},
		}
		remote := map[string]registrationEntry{
			normalizedPubkey: {
				FeeRecipient: "0x000000000000000000000000000000000000bbbb",
				GasLimit:     22222,
				Timestamp:    equalTS,
			},
		}

		entries := resolveLatestRegistrations(lock, overrides, remote, nil)
		require.Len(t, entries, 2)

		require.Equal(t, "0x000000000000000000000000000000000000bbbb", entries[0].FeeRecipient)
		require.Equal(t, []string{"overrides", "remote"}, entries[0].Sources)
	})

	t.Run("override and remote diverge, override wins by timestamp", func(t *testing.T) {
		overrides := map[string]registrationEntry{
			normalizedPubkey: {
				FeeRecipient: "0x000000000000000000000000000000000000cccc",
				GasLimit:     33333,
				Timestamp:    lockTimestamp.Add(2 * time.Hour),
			},
		}
		remote := map[string]registrationEntry{
			normalizedPubkey: {
				FeeRecipient: "0x000000000000000000000000000000000000dddd",
				GasLimit:     44444,
				Timestamp:    lockTimestamp.Add(time.Hour),
			},
		}

		entries := resolveLatestRegistrations(lock, overrides, remote, nil)
		require.Len(t, entries, 2)

		require.Equal(t, "0x000000000000000000000000000000000000cccc", entries[0].FeeRecipient)
		require.Equal(t, []string{"overrides"}, entries[0].Sources)
	})

	t.Run("remote newer than override, remote wins", func(t *testing.T) {
		overrides := map[string]registrationEntry{
			normalizedPubkey: {
				FeeRecipient: "0x000000000000000000000000000000000000eeee",
				GasLimit:     55555,
				Timestamp:    lockTimestamp.Add(time.Hour),
			},
		}
		remote := map[string]registrationEntry{
			normalizedPubkey: {
				FeeRecipient: "0x000000000000000000000000000000000000ffff",
				GasLimit:     66666,
				Timestamp:    lockTimestamp.Add(2 * time.Hour),
			},
		}

		entries := resolveLatestRegistrations(lock, overrides, remote, nil)
		require.Len(t, entries, 2)

		require.Equal(t, "0x000000000000000000000000000000000000ffff", entries[0].FeeRecipient)
		require.Equal(t, []string{"remote"}, entries[0].Sources)
	})
}

func TestFeeRecipientListCLI(t *testing.T) {
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
				"--overrides-file=test",
			},
		},
		{
			name:        "correct flags with pubkeys",
			expectedErr: "read cluster-lock.json: open test: no such file or directory",
			flags: []string{
				"--lock-file=test",
				"--overrides-file=test",
				"--validator-public-keys=0x" + strings.Repeat("ab", 48),
			},
		},
		{
			name:        "correct flags with publish flags",
			expectedErr: "read cluster-lock.json: open test: no such file or directory",
			flags: []string{
				"--lock-file=test",
				"--overrides-file=test",
				"--publish-address=http://example.test",
				"--publish-timeout=2s",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := newFeeRecipientCmd(newFeeRecipientListCmd(runFeeRecipientList))
			cmd.SetArgs(append([]string{"list"}, test.flags...))

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

func TestFeeRecipientListFetchesRemote(t *testing.T) {
	ctx := t.Context()
	ctx = log.WithCtx(ctx, z.Str("test_case", t.Name()))

	valAmt := 4
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

	handler, addLockFiles := obolapimock.MockServer(false, nil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	addLockFiles(lock)

	// Submit partial signatures from threshold operators so the API has quorum.
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

	overridesFile := filepath.Join(root, "output", "builder_registrations_overrides.json")

	listConfig := feerecipientListConfig{
		feerecipientConfig: feerecipientConfig{
			LockFilePath:      filepath.Join(root, "op0", "cluster-lock.json"),
			OverridesFilePath: overridesFile,
			PublishAddress:    srv.URL,
			PublishTimeout:    10 * time.Second,
		},
	}

	require.NoError(t, runFeeRecipientList(ctx, listConfig))

	// list must not write to disk.
	_, err = os.Stat(overridesFile)
	require.True(t, os.IsNotExist(err), "list must not write the overrides file")
}

func TestFeeRecipientListRemoteOnlyTriggersSuggestion(t *testing.T) {
	logs := initLogCapture(t)
	ctx := t.Context()

	valAmt := 4
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

	handler, addLockFiles := obolapimock.MockServer(false, nil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	addLockFiles(lock)

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
		require.NoError(t, runFeeRecipientSign(ctx, signConfig))
	}

	listConfig := feerecipientListConfig{
		feerecipientConfig: feerecipientConfig{
			LockFilePath:      filepath.Join(root, "op0", "cluster-lock.json"),
			OverridesFilePath: filepath.Join(t.TempDir(), "nonexistent-overrides.json"),
			PublishAddress:    srv.URL,
			PublishTimeout:    10 * time.Second,
		},
	}

	require.NoError(t, runFeeRecipientList(ctx, listConfig))

	output := logs.String()

	require.Regexp(t,
		`Builder registration for `+regexp.QuoteMeta(validatorPubkey)+`[^\n]*source=remote`,
		output,
	)
	require.Contains(t, output, "Updated registrations are available")
}

func TestFeeRecipientListOverridesMatchRemote(t *testing.T) {
	logs := initLogCapture(t)
	ctx := t.Context()

	valAmt := 4
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

	handler, addLockFiles := obolapimock.MockServer(false, nil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	addLockFiles(lock)

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
		require.NoError(t, runFeeRecipientSign(ctx, signConfig))
	}

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

	listConfig := feerecipientListConfig{
		feerecipientConfig: feerecipientConfig{
			LockFilePath:      filepath.Join(root, "op0", "cluster-lock.json"),
			OverridesFilePath: overridesFile,
			PublishAddress:    srv.URL,
			PublishTimeout:    10 * time.Second,
		},
	}
	require.NoError(t, runFeeRecipientList(ctx, listConfig))

	output := logs.String()

	require.Regexp(t,
		`Builder registration for `+regexp.QuoteMeta(validatorPubkey)+`[^\n]*source=overrides\+remote`,
		output,
	)
	require.NotContains(t, output, "Updated registrations are available")
}

func TestFeeRecipientListRemoteUnreachable(t *testing.T) {
	logs := initLogCapture(t)
	ctx := t.Context()

	valAmt := 4
	operatorAmt := 4

	random := rand.New(rand.NewSource(0))
	lock, _, _ := cluster.NewForT(t, valAmt, operatorAmt, operatorAmt, 0, random)

	lockJSON, err := json.Marshal(lock)
	require.NoError(t, err)

	lockFile := filepath.Join(t.TempDir(), "cluster-lock.json")
	require.NoError(t, os.WriteFile(lockFile, lockJSON, 0o644))

	// Start and immediately close the server so the URL is unreachable.
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()

	listConfig := feerecipientListConfig{
		feerecipientConfig: feerecipientConfig{
			LockFilePath:      lockFile,
			OverridesFilePath: filepath.Join(t.TempDir(), "nonexistent-overrides.json"),
			PublishAddress:    srv.URL,
			PublishTimeout:    500 * time.Millisecond,
		},
	}

	require.NoError(t, runFeeRecipientList(ctx, listConfig))

	output := logs.String()

	require.Contains(t, output, "Unable to fetch remote builder registrations")
	require.NotContains(t, output, "Updated registrations are available")
	require.NotContains(t, output, "Validators with partial builder registrations")
	require.NotContains(t, output, "Validators unknown to remote API")
}

func TestFeeRecipientListIncompleteNoQuorum(t *testing.T) {
	logs := initLogCapture(t)
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

	// dropOnePsig=true prevents quorum from being reached.
	handler, addLockFiles := obolapimock.MockServer(true, nil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	addLockFiles(lock)

	// Submit partials from fewer than threshold operators so the API reports
	// the registration as incomplete (below quorum).
	newFeeRecipient := "0x0000000000000000000000000000000000001234"

	validatorPubkey := lock.Validators[0].PublicKeyHex()
	for opIdx := range lock.Threshold - 1 {
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
		require.NoError(t, runFeeRecipientSign(ctx, signConfig))
	}

	listConfig := feerecipientListConfig{
		feerecipientConfig: feerecipientConfig{
			LockFilePath:      filepath.Join(root, "op0", "cluster-lock.json"),
			OverridesFilePath: filepath.Join(t.TempDir(), "nonexistent-overrides.json"),
			PublishAddress:    srv.URL,
			PublishTimeout:    10 * time.Second,
		},
	}

	require.NoError(t, runFeeRecipientList(ctx, listConfig))

	output := logs.String()

	require.Contains(t, output, "Validators with partial builder registrations on remote")
	require.NotContains(t, output, "Updated registrations are available")
	require.Regexp(t,
		`Builder registration for `+regexp.QuoteMeta(validatorPubkey)+`[^\n]*source=lock`,
		output,
	)
}

func TestRemoteOnlyPubkeys(t *testing.T) {
	type entry struct {
		pubkey  string
		sources []string
	}

	cases := []struct {
		name    string
		entries []entry
		want    []string
	}{
		{"empty", nil, nil},
		{"lock only", []entry{{"pk1", []string{"lock"}}}, nil},
		{"overrides only", []entry{{"pk1", []string{"overrides"}}}, nil},
		{"remote only", []entry{{"pk1", []string{"remote"}}}, []string{"pk1"}},
		{"lock+remote (remote matches lock default)", []entry{{"pk1", []string{"lock", "remote"}}}, nil},
		{"overrides+remote (already synced)", []entry{{"pk1", []string{"overrides", "remote"}}}, nil},
		{"lock+overrides+remote", []entry{{"pk1", []string{"lock", "overrides", "remote"}}}, nil},
		{"mixed", []entry{
			{"pk1", []string{"lock"}},
			{"pk2", []string{"remote"}},
			{"pk3", []string{"lock", "remote"}},
			{"pk4", []string{"remote"}},
			{"pk5", []string{"overrides", "remote"}},
		}, []string{"pk2", "pk4"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries := make([]registrationEntry, len(tc.entries))
			for i, e := range tc.entries {
				entries[i] = registrationEntry{Pubkey: e.pubkey, Sources: e.sources}
			}

			require.Equal(t, tc.want, remoteOnlyPubkeys(entries))
		})
	}
}

// initLogCapture points the process-global charon logger at a logfmt-encoded
// buffer for the duration of the test and returns the buffer. Tests read the
// buffer contents (as text) to assert on "key=value" pairs. Tests using this
// helper must not run with t.Parallel(), since it mutates global state.
func initLogCapture(t *testing.T) *zaptest.Buffer {
	t.Helper()

	buf := &zaptest.Buffer{}
	log.InitLogfmtForT(t, buf)

	return buf
}
