// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/registration"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
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
		LockFilePath:      lockFile,
		OverridesFilePath: filepath.Join(t.TempDir(), "nonexistent-overrides.json"),
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
		ValidatorPublicKeys: []string{lock.Validators[0].PublicKeyHex()},
		LockFilePath:        lockFile,
		OverridesFilePath:   filepath.Join(t.TempDir(), "nonexistent-overrides.json"),
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
		ValidatorPublicKeys: []string{"0x" + strings.Repeat("ab", 48)},
		LockFilePath:        lockFile,
		OverridesFilePath:   filepath.Join(t.TempDir(), "nonexistent-overrides.json"),
	}

	err = runFeeRecipientList(t.Context(), config)
	require.ErrorContains(t, err, "validator pubkey not found in cluster lock")
}

func TestFeeRecipientListInvalidLockFile(t *testing.T) {
	config := feerecipientListConfig{
		LockFilePath:      "nonexistent-lock.json",
		OverridesFilePath: filepath.Join(t.TempDir(), "nonexistent-overrides.json"),
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
		LockFilePath:      lockFile,
		OverridesFilePath: overridesFile,
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
		entries := resolveLatestRegistrations(lock, nil, nil)
		require.Len(t, entries, 2)

		require.Equal(t, lock.Validators[0].PublicKeyHex(), entries[0].Pubkey)
		require.Equal(t, "0x"+hex.EncodeToString(lock.Validators[0].BuilderRegistration.Message.FeeRecipient), entries[0].FeeRecipient)
		require.Equal(t, uint64(lock.Validators[0].BuilderRegistration.Message.GasLimit), entries[0].GasLimit)
	})

	t.Run("override with newer timestamp wins", func(t *testing.T) {
		overrides := map[string]registrationEntry{
			normalizedPubkey: {
				FeeRecipient: "0x0000000000000000000000000000000000005678",
				GasLimit:     99999,
				Timestamp:    lockTimestamp.Add(time.Hour),
			},
		}

		entries := resolveLatestRegistrations(lock, overrides, nil)
		require.Len(t, entries, 2)

		require.Equal(t, "0x0000000000000000000000000000000000005678", entries[0].FeeRecipient)
		require.Equal(t, uint64(99999), entries[0].GasLimit)
	})

	t.Run("override with older timestamp loses", func(t *testing.T) {
		overrides := map[string]registrationEntry{
			normalizedPubkey: {
				FeeRecipient: "0x0000000000000000000000000000000000005678",
				GasLimit:     99999,
				Timestamp:    lockTimestamp.Add(-time.Hour),
			},
		}

		entries := resolveLatestRegistrations(lock, overrides, nil)
		require.Len(t, entries, 2)

		// Should keep lock values.
		require.Equal(t, "0x"+hex.EncodeToString(lock.Validators[0].BuilderRegistration.Message.FeeRecipient), entries[0].FeeRecipient)
		require.Equal(t, uint64(lock.Validators[0].BuilderRegistration.Message.GasLimit), entries[0].GasLimit)
	})

	t.Run("pubkey filter", func(t *testing.T) {
		filter := map[string]struct{}{
			normalizedPubkey: {},
		}

		entries := resolveLatestRegistrations(lock, nil, filter)
		require.Len(t, entries, 1)
		require.Equal(t, lock.Validators[0].PublicKeyHex(), entries[0].Pubkey)
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
