// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"encoding/json"
	"maps"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/registration"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

func TestLoadBuilderRegistrationOverrides(t *testing.T) {
	t.Run("file not found", func(t *testing.T) {
		regs, err := LoadBuilderRegistrationOverrides(filepath.Join(t.TempDir(), "missing.json"), eth2p0.Version{})
		require.NoError(t, err)
		require.Nil(t, regs)
	})

	t.Run("invalid json", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.json")
		require.NoError(t, os.WriteFile(path, []byte("not json"), 0o644))

		_, err := LoadBuilderRegistrationOverrides(path, eth2p0.Version{})
		require.ErrorContains(t, err, "unmarshal builder registration overrides file")
	})

	t.Run("valid without verification", func(t *testing.T) {
		regs := []*eth2api.VersionedSignedValidatorRegistration{
			makeUnsignedOverride(t),
		}

		path := writeOverridesFile(t, regs)

		loaded, err := LoadBuilderRegistrationOverrides(path, eth2p0.Version{})
		require.NoError(t, err)
		require.Len(t, loaded, 1)
	})

	t.Run("valid with signature verification", func(t *testing.T) {
		lock, regs := makeSignedOverrides(t)

		path := writeOverridesFile(t, regs)

		loaded, err := LoadBuilderRegistrationOverrides(path, eth2p0.Version(lock.ForkVersion))
		require.NoError(t, err)
		require.Len(t, loaded, len(regs))
	})

	t.Run("invalid signature", func(t *testing.T) {
		lock, regs := makeSignedOverrides(t)

		// Corrupt the signature.
		regs[0].V1.Signature[0] ^= 0xff

		path := writeOverridesFile(t, regs)

		_, err := LoadBuilderRegistrationOverrides(path, eth2p0.Version(lock.ForkVersion))
		require.ErrorContains(t, err, "verify builder registration override signature")
	})
}

func Test_applyBuilderRegistrationOverrides(t *testing.T) {
	lock, _ := makeSignedOverrides(t)
	ctx := t.Context()

	// Build base registrations from the lock.
	var baseRegs []*eth2api.VersionedSignedValidatorRegistration

	feeRecipientByPubkey := make(map[core.PubKey]string)

	for _, val := range lock.Validators {
		reg, err := val.Eth2Registration()
		require.NoError(t, err)

		baseRegs = append(baseRegs, reg)
		corePubkey, err := core.PubKeyFromBytes(val.PubKey)
		require.NoError(t, err)

		feeRecipientByPubkey[corePubkey] = "0x" + lock.FeeRecipientAddresses()[0]
	}

	t.Run("no overrides", func(t *testing.T) {
		feeMap := maps.Clone(feeRecipientByPubkey)
		result := applyBuilderRegistrationOverrides(ctx, baseRegs, nil, feeMap)
		require.Equal(t, baseRegs, result)
	})

	t.Run("override with newer timestamp wins", func(t *testing.T) {
		feeMap := maps.Clone(feeRecipientByPubkey)

		newFeeRecipient := bellatrix.ExecutionAddress{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAB, 0xCD}
		override := &eth2api.VersionedSignedValidatorRegistration{
			Version: eth2spec.BuilderVersionV1,
			V1: &eth2v1.SignedValidatorRegistration{
				Message: &eth2v1.ValidatorRegistration{
					FeeRecipient: newFeeRecipient,
					GasLimit:     42000,
					Timestamp:    baseRegs[0].V1.Message.Timestamp.Add(time.Hour),
					Pubkey:       baseRegs[0].V1.Message.Pubkey,
				},
			},
		}

		result := applyBuilderRegistrationOverrides(ctx, baseRegs, []*eth2api.VersionedSignedValidatorRegistration{override}, feeMap)

		require.Equal(t, override, result[0])

		corePubkey, err := core.PubKeyFromBytes(baseRegs[0].V1.Message.Pubkey[:])
		require.NoError(t, err)
		require.Contains(t, feeMap[corePubkey], "abcd")
	})

	t.Run("override with older timestamp loses", func(t *testing.T) {
		feeMap := maps.Clone(feeRecipientByPubkey)

		override := &eth2api.VersionedSignedValidatorRegistration{
			Version: eth2spec.BuilderVersionV1,
			V1: &eth2v1.SignedValidatorRegistration{
				Message: &eth2v1.ValidatorRegistration{
					FeeRecipient: bellatrix.ExecutionAddress{},
					GasLimit:     42000,
					Timestamp:    baseRegs[0].V1.Message.Timestamp.Add(-time.Hour),
					Pubkey:       baseRegs[0].V1.Message.Pubkey,
				},
			},
		}

		result := applyBuilderRegistrationOverrides(ctx, baseRegs, []*eth2api.VersionedSignedValidatorRegistration{override}, feeMap)

		require.Equal(t, baseRegs[0], result[0])
	})

	t.Run("unknown pubkey ignored", func(t *testing.T) {
		feeMap := maps.Clone(feeRecipientByPubkey)

		override := &eth2api.VersionedSignedValidatorRegistration{
			Version: eth2spec.BuilderVersionV1,
			V1: &eth2v1.SignedValidatorRegistration{
				Message: &eth2v1.ValidatorRegistration{
					FeeRecipient: bellatrix.ExecutionAddress{},
					GasLimit:     42000,
					Timestamp:    time.Now().Add(time.Hour),
					Pubkey:       eth2p0.BLSPubKey{0x99},
				},
			},
		}

		result := applyBuilderRegistrationOverrides(ctx, baseRegs, []*eth2api.VersionedSignedValidatorRegistration{override}, feeMap)

		for i := range baseRegs {
			require.Equal(t, baseRegs[i], result[i])
		}
	})
}

func TestBuilderRegistrationService(t *testing.T) {
	lock, overrides := makeSignedOverrides(t)
	ctx := t.Context()

	// Build base registrations and fee recipients from the lock.
	var baseRegs []*eth2api.VersionedSignedValidatorRegistration

	baseFeeRecipients := make(map[core.PubKey]string)

	for vi, val := range lock.Validators {
		reg, err := val.Eth2Registration()
		require.NoError(t, err)

		baseRegs = append(baseRegs, reg)

		corePubkey, err := core.PubKeyFromBytes(val.PubKey)
		require.NoError(t, err)

		baseFeeRecipients[corePubkey] = lock.FeeRecipientAddresses()[vi]
	}

	t.Run("no overrides file", func(t *testing.T) {
		svc, err := NewBuilderRegistrationService(ctx, "", eth2p0.Version{}, baseRegs, baseFeeRecipients)
		require.NoError(t, err)

		require.Equal(t, baseRegs, svc.Registrations())

		for pk, addr := range baseFeeRecipients {
			require.Equal(t, addr, svc.FeeRecipient(pk))
		}
	})

	t.Run("initial load with overrides", func(t *testing.T) {
		path := writeOverridesFile(t, overrides)

		svc, err := NewBuilderRegistrationService(ctx, path, eth2p0.Version(lock.ForkVersion), baseRegs, baseFeeRecipients)
		require.NoError(t, err)

		regs := svc.Registrations()
		require.Len(t, regs, len(baseRegs))

		// Overrides have newer timestamps, so they should win.
		for i, reg := range regs {
			require.Equal(t, overrides[i].V1.Message.FeeRecipient, reg.V1.Message.FeeRecipient)
		}
	})

	t.Run("file watcher reloads on change", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "overrides.json")

		// Start without overrides file.
		svc, err := NewBuilderRegistrationService(ctx, path, eth2p0.Version(lock.ForkVersion), baseRegs, baseFeeRecipients)
		require.NoError(t, err)
		require.Equal(t, baseRegs, svc.Registrations())

		// Start the watcher.
		watchCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		go svc.Run(watchCtx)

		// Give the watcher time to start.
		time.Sleep(100 * time.Millisecond)

		// Write the overrides file.
		data, err := json.Marshal(overrides)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, data, 0o644))

		// Wait for debounce + reload.
		require.Eventually(t, func() bool {
			regs := svc.Registrations()
			if len(regs) != len(overrides) {
				return false
			}

			return regs[0].V1.Message.FeeRecipient == overrides[0].V1.Message.FeeRecipient
		}, 3*time.Second, 100*time.Millisecond)

		// Verify fee recipients were also updated.
		corePubkey, err := core.PubKeyFromBytes(lock.Validators[0].PubKey)
		require.NoError(t, err)
		require.Contains(t, svc.FeeRecipient(corePubkey), "9900")
	})
}

// makeSignedOverrides creates a test cluster lock and properly signed builder registration overrides.
func makeSignedOverrides(t *testing.T) (cluster.Lock, []*eth2api.VersionedSignedValidatorRegistration) {
	t.Helper()

	random := rand.New(rand.NewSource(0))
	lock, _, keyShares := cluster.NewForT(t, 2, 4, 4, 0, random)

	forkVersion, err := eth2util.NetworkToForkVersionBytes(eth2util.Goerli.Name)
	require.NoError(t, err)

	var overrides []*eth2api.VersionedSignedValidatorRegistration

	for valIdx, val := range lock.Validators {
		// Reconstruct root secret from shares.
		sharesMap := make(map[int]tbls.PrivateKey)
		for i, share := range keyShares[valIdx] {
			sharesMap[i+1] = share
		}

		rootSecret, err := tbls.RecoverSecret(sharesMap, uint(len(keyShares[valIdx])), uint(lock.Threshold))
		require.NoError(t, err)

		pubkey, err := tblsconv.PubkeyToETH2(tbls.PublicKey(val.PubKey))
		require.NoError(t, err)

		feeRecipient := bellatrix.ExecutionAddress{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x99, byte(valIdx)}

		msg := &eth2v1.ValidatorRegistration{
			FeeRecipient: feeRecipient,
			GasLimit:     registration.DefaultGasLimit,
			Timestamp:    time.Now().Add(time.Hour),
			Pubkey:       pubkey,
		}

		sigRoot, err := registration.GetMessageSigningRoot(msg, eth2p0.Version(forkVersion))
		require.NoError(t, err)

		sig, err := tbls.Sign(rootSecret, sigRoot[:])
		require.NoError(t, err)

		overrides = append(overrides, &eth2api.VersionedSignedValidatorRegistration{
			Version: eth2spec.BuilderVersionV1,
			V1: &eth2v1.SignedValidatorRegistration{
				Message:   msg,
				Signature: eth2p0.BLSSignature(sig),
			},
		})
	}

	return lock, overrides
}

// makeUnsignedOverride creates a minimal override without a valid signature.
func makeUnsignedOverride(t *testing.T) *eth2api.VersionedSignedValidatorRegistration {
	t.Helper()

	return &eth2api.VersionedSignedValidatorRegistration{
		Version: eth2spec.BuilderVersionV1,
		V1: &eth2v1.SignedValidatorRegistration{
			Message: &eth2v1.ValidatorRegistration{
				FeeRecipient: bellatrix.ExecutionAddress{0x01},
				GasLimit:     30000000,
				Timestamp:    time.Now(),
				Pubkey:       eth2p0.BLSPubKey{0x01},
			},
		},
	}
}

func writeOverridesFile(t *testing.T, regs []*eth2api.VersionedSignedValidatorRegistration) string {
	t.Helper()

	data, err := json.Marshal(regs)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "overrides.json")
	require.NoError(t, os.WriteFile(path, data, 0o644))

	return path
}
