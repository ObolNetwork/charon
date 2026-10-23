// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster_test

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"strings"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
)

func TestVerifyLock(t *testing.T) {
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := cluster.NewForT(t, 3, 3, 4, seed, random)
	require.NoError(t, lock.Definition.VerifySignatures(nil))
	require.NoError(t, lock.VerifySignatures(nil))
}

func TestVerifyLockRejectsMismatchedPublicShares(t *testing.T) {
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := cluster.NewForT(t, 3, 3, 4, seed, random)

	// Tamper validator shares so they no longer reconstruct validator 0 group key.
	lock.Validators[0].PubShares = append([][]byte(nil), lock.Validators[1].PubShares...)

	err := lock.VerifySignatures(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "public shares do not reconstruct distributed public key")
}

func TestVerifyLockRejectsDuplicateDistributedKeys(t *testing.T) {
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := cluster.NewForT(t, 3, 3, 4, seed, random)

	// Duplicate validator 0 so two entries share the same distributed public key.
	lock.Validators = append(lock.Validators, lock.Validators[0])

	err := lock.VerifySignatures(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate distributed validator public key")
}

func TestVerifyLockRejectsExtraShareNotOnPolynomial(t *testing.T) {
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := cluster.NewForT(t, 1, 3, 4, seed, random)

	// Keep first threshold (3) shares intact so the main reconstruction passes;
	// replace the extra share with the DV pubkey — a valid, unique, non-identity
	// G1 point that does not lie on the share polynomial.
	lock.Validators[0].PubShares[3] = append([]byte(nil), lock.Validators[0].PubKey...)

	err := lock.VerifySignatures(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "extra share does not lie on distributed key polynomial")
}

func TestVerifyLockRejectsValidatorCountMismatch(t *testing.T) {
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := cluster.NewForT(t, 2, 3, 4, seed, random)

	// Tamper definition to claim fewer validators than the lock contains,
	// then recompute all hashes so they verify correctly (models the attack).
	lock.NumValidators = 1
	lock.ValidatorAddresses = lock.ValidatorAddresses[:1]

	def, err := lock.SetDefinitionHashes()
	require.NoError(t, err)

	lock.Definition = def

	lock, err = lock.SetLockHash()
	require.NoError(t, err)

	err = lock.VerifyHashes()
	require.Error(t, err)
	require.Contains(t, err.Error(), "lock validators count mismatch")
}

func TestVerifyLockRejectsDuplicatePublicShares(t *testing.T) {
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := cluster.NewForT(t, 3, 3, 4, seed, random)

	// Duplicate one share so the share list is not unique.
	lock.Validators[0].PubShares[1] = append([]byte(nil), lock.Validators[0].PubShares[0]...)

	err := lock.VerifySignatures(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate public share")
}

// newLockWithDepositsForT returns a signed lock of the provided version populated with valid deposit data
// for each of the definition's deposit amounts (or defaults), as well as the p2p keys and secret shares.
func newLockWithDepositsForT(t *testing.T, version string, compounding bool) (cluster.Lock, []*k1.PrivateKey, [][]tbls.PrivateKey) {
	t.Helper()

	const seed = 1

	lock, p2pKeys, shares := cluster.NewForT(t, 2, 3, 4, seed, rand.New(rand.NewSource(seed)), func(d *cluster.Definition) {
		d.Version = version
		d.Compounding = compounding

		if isAnyVersion(version, v1_6, v1_7, v1_8, v1_9) {
			d.TargetGasLimit = 0
		}
	})

	amounts := lock.DepositAmounts
	if len(amounts) == 0 {
		amounts = deposit.DefaultDepositAmounts(compounding)
		if isAnyVersion(version, v1_6, v1_7) {
			amounts = []eth2p0.Gwei{deposit.DefaultDepositAmount}
		}
	}

	for i := range lock.Validators {
		if isAnyVersion(version, v1_6) {
			lock.Validators[i].BuilderRegistration = cluster.BuilderRegistration{} // Not supported before v1.7.
		}

		lock.Validators[i].PartialDepositData = nil
		for _, amount := range amounts {
			lock.Validators[i].PartialDepositData = append(lock.Validators[i].PartialDepositData,
				signDepositForT(t, lock, shares[i], i, amount, compounding))
		}
	}

	return resignLockForT(t, lock, p2pKeys, shares), p2pKeys, shares
}

// signDepositForT returns deposit data for the validator at index i signed with the validator's root secret.
func signDepositForT(t *testing.T, lock cluster.Lock, shares []tbls.PrivateKey, i int, amount eth2p0.Gwei, compounding bool) cluster.DepositData {
	t.Helper()

	shareMap := make(map[int]tbls.PrivateKey)
	for idx, share := range shares {
		shareMap[idx+1] = share
	}

	secret, err := tbls.RecoverSecret(shareMap, uint(len(shares)), uint(lock.Threshold))
	require.NoError(t, err)

	msg, err := deposit.NewMessage(eth2p0.BLSPubKey(lock.Validators[i].PubKey), lock.ValidatorAddresses[i].WithdrawalAddress, amount, compounding)
	require.NoError(t, err)

	root, err := deposit.GetMessageSigningRootByForkVersion(msg, eth2p0.Version(lock.ForkVersion))
	require.NoError(t, err)

	sig, err := tbls.Sign(secret, root[:])
	require.NoError(t, err)

	return cluster.DepositData{
		PubKey:                msg.PublicKey[:],
		WithdrawalCredentials: msg.WithdrawalCredentials,
		Amount:                int(msg.Amount),
		Signature:             sig[:],
	}
}

// resignLockForT returns the lock with recalculated lock hash, aggregate signature and node signatures.
func resignLockForT(t *testing.T, lock cluster.Lock, p2pKeys []*k1.PrivateKey, shares [][]tbls.PrivateKey) cluster.Lock {
	t.Helper()

	lock, err := lock.SetLockHash()
	require.NoError(t, err)

	var sigs []tbls.Signature

	for _, dvShares := range shares {
		for _, share := range dvShares {
			sig, err := tbls.Sign(share, lock.LockHash)
			require.NoError(t, err)

			sigs = append(sigs, sig)
		}
	}

	aggSig, err := tbls.Aggregate(sigs)
	require.NoError(t, err)

	lock.SignatureAggregate = aggSig[:]

	if lock.NodeSignatures != nil {
		lock.NodeSignatures = nil
		for _, p2pKey := range p2pKeys {
			nodeSig, err := k1util.Sign(p2pKey, lock.LockHash)
			require.NoError(t, err)

			lock.NodeSignatures = append(lock.NodeSignatures, nodeSig)
		}
	}

	return lock
}

func TestVerifyLockDepositData(t *testing.T) {
	for _, version := range []string{v1_6, v1_7, v1_8, v1_9, v1_10, v1_11} {
		t.Run(version, func(t *testing.T) {
			lock, _, _ := newLockWithDepositsForT(t, version, false)
			require.NotEmpty(t, lock.Validators[0].PartialDepositData)
			require.NoError(t, lock.VerifyHashes())
			require.NoError(t, lock.VerifySignatures(nil))

			// Ensure it survives a json roundtrip.
			b, err := json.Marshal(lock)
			require.NoError(t, err)

			var lock2 cluster.Lock
			require.NoError(t, json.Unmarshal(b, &lock2))
			require.NoError(t, lock2.VerifyHashes())
			require.NoError(t, lock2.VerifySignatures(nil))
		})
	}

	t.Run("compounding", func(t *testing.T) {
		lock, _, _ := newLockWithDepositsForT(t, v1_11, true)
		require.Len(t, lock.Validators[0].PartialDepositData, len(deposit.DefaultDepositAmounts(true)))
		require.Equal(t, byte(0x02), lock.Validators[0].PartialDepositData[0].WithdrawalCredentials[0])
		require.NoError(t, lock.VerifySignatures(nil))
	})

	t.Run("absent deposit data", func(t *testing.T) {
		for _, version := range []string{v1_7, v1_11} {
			lock, p2pKeys, shares := newLockWithDepositsForT(t, version, false)
			for i := range lock.Validators {
				if isAnyVersion(version, v1_7) {
					// v1.6 and v1.7 locks in the wild contain zero valued deposit data.
					lock.Validators[i].PartialDepositData = []cluster.DepositData{{}}
				} else {
					lock.Validators[i].PartialDepositData = nil
				}
			}

			lock = resignLockForT(t, lock, p2pKeys, shares)
			require.NoError(t, lock.VerifySignatures(nil))
		}
	})
}

func TestVerifyLockRejectsInvalidDepositData(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		compounding bool
		tamper      func(t *testing.T, lock cluster.Lock, shares [][]tbls.PrivateKey) cluster.Lock
		errMsg      string
	}{
		{
			name:    "bad signature",
			version: v1_11,
			tamper: func(_ *testing.T, lock cluster.Lock, _ [][]tbls.PrivateKey) cluster.Lock {
				// Use the signature of another amount.
				dd := lock.Validators[0].PartialDepositData
				dd[0].Signature = dd[1].Signature

				return lock
			},
			errMsg: "verify deposit data signature",
		},
		{
			name:    "bad signature v1.7",
			version: v1_7,
			tamper: func(_ *testing.T, lock cluster.Lock, _ [][]tbls.PrivateKey) cluster.Lock {
				lock.Validators[0].PartialDepositData[0].Signature = lock.Validators[1].PartialDepositData[0].Signature
				return lock
			},
			errMsg: "verify deposit data signature",
		},
		{
			name:    "wrong withdrawal credentials",
			version: v1_11,
			tamper: func(t *testing.T, lock cluster.Lock, shares [][]tbls.PrivateKey) cluster.Lock {
				t.Helper()

				// Validly signed deposit for a different withdrawal address.
				orig := lock.ValidatorAddresses[0].WithdrawalAddress
				lock.ValidatorAddresses[0].WithdrawalAddress = testutil.RandomETHAddress()
				dd := signDepositForT(t, lock, shares[0], 0, deposit.DefaultDepositAmount, false)
				lock.ValidatorAddresses[0].WithdrawalAddress = orig
				lock.Validators[0].PartialDepositData[1] = dd

				return lock
			},
			errMsg: "deposit withdrawal credentials don't match definition withdrawal address",
		},
		{
			name:        "0x01 credentials for compounding definition",
			version:     v1_11,
			compounding: true,
			tamper: func(t *testing.T, lock cluster.Lock, shares [][]tbls.PrivateKey) cluster.Lock {
				t.Helper()

				lock.Validators[0].PartialDepositData[0] = signDepositForT(t, lock, shares[0], 0, deposit.MinDepositAmount, false)

				return lock
			},
			errMsg: "deposit withdrawal credentials don't match definition withdrawal address",
		},
		{
			name:    "0x02 credentials for non-compounding definition",
			version: v1_11,
			tamper: func(t *testing.T, lock cluster.Lock, shares [][]tbls.PrivateKey) cluster.Lock {
				t.Helper()

				lock.Validators[0].PartialDepositData[0] = signDepositForT(t, lock, shares[0], 0, deposit.MinDepositAmount, true)

				return lock
			},
			errMsg: "deposit withdrawal credentials don't match definition withdrawal address",
		},
		{
			name:    "amount not in definition",
			version: v1_11,
			tamper: func(t *testing.T, lock cluster.Lock, shares [][]tbls.PrivateKey) cluster.Lock {
				t.Helper()

				lock.Validators[0].PartialDepositData[0] = signDepositForT(t, lock, shares[0], 0, 2*deposit.MinDepositAmount, false)

				return lock
			},
			errMsg: "deposit amount not in definition deposit amounts",
		},
		{
			name:    "pubkey mismatch",
			version: v1_11,
			tamper: func(_ *testing.T, lock cluster.Lock, _ [][]tbls.PrivateKey) cluster.Lock {
				lock.Validators[0].PartialDepositData[0] = lock.Validators[1].PartialDepositData[0]
				return lock
			},
			errMsg: "deposit data pubkey doesn't match distributed validator pubkey",
		},
		{
			name:    "zero valued partial deposit data",
			version: v1_11,
			tamper: func(_ *testing.T, lock cluster.Lock, _ [][]tbls.PrivateKey) cluster.Lock {
				lock.Validators[0].PartialDepositData[0] = cluster.DepositData{}
				return lock
			},
			errMsg: "deposit data pubkey doesn't match distributed validator pubkey",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lock, p2pKeys, shares := newLockWithDepositsForT(t, tt.version, tt.compounding)
			require.NoError(t, lock.VerifySignatures(nil))

			lock = tt.tamper(t, lock, shares)
			lock = resignLockForT(t, lock, p2pKeys, shares)
			require.NoError(t, lock.VerifyHashes())

			err := lock.VerifySignatures(nil)
			require.ErrorContains(t, err, "verify deposit data")
			require.ErrorContains(t, err, tt.errMsg)
		})
	}
}

func TestHashRejectsShortWithdrawalCredentials(t *testing.T) {
	lock, _, _ := newLockWithDepositsForT(t, v1_11, false)

	// A 20 byte withdrawal credential (just the address) would be left padded to 32 bytes
	// and hash identically to 0x000...<address> credentials.
	creds := lock.Validators[0].PartialDepositData[0].WithdrawalCredentials
	lock.Validators[0].PartialDepositData[0].WithdrawalCredentials = creds[12:]

	_, err := lock.SetLockHash()
	require.ErrorContains(t, err, "invalid fixed size bytes length")

	require.ErrorContains(t, lock.VerifyHashes(), "invalid fixed size bytes length")
}

// TestUnmarshalRejectsInvalidFieldLengths ensures fixed size fields with invalid lengths are rejected when parsing.
func TestUnmarshalRejectsInvalidFieldLengths(t *testing.T) {
	lock, _, _ := newLockWithDepositsForT(t, v1_11, false)

	b, err := json.Marshal(lock)
	require.NoError(t, err)

	short := func(hex string, n int) string { return hex[:len(hex)-2*n] }
	long := func(hex string) string { return hex + "00" }

	tests := []struct {
		name   string
		mutate func(m map[string]any)
		field  string
	}{
		{
			name: "20 byte withdrawal credentials",
			mutate: func(m map[string]any) {
				dd := depositJSON(m, 0, 0)
				dd["withdrawal_credentials"] = "0x" + dd["withdrawal_credentials"].(string)[2+24:]
			},
			field: "deposit_data_withdrawal_credentials",
		},
		{
			name: "33 byte withdrawal credentials",
			mutate: func(m map[string]any) {
				dd := depositJSON(m, 0, 0)
				dd["withdrawal_credentials"] = long(dd["withdrawal_credentials"].(string))
			},
			field: "deposit_data_withdrawal_credentials",
		},
		{
			name: "short deposit signature",
			mutate: func(m map[string]any) {
				dd := depositJSON(m, 0, 1)
				dd["signature"] = short(dd["signature"].(string), 1)
			},
			field: "deposit_data_signature",
		},
		{
			name: "short deposit pubkey",
			mutate: func(m map[string]any) {
				dd := depositJSON(m, 1, 0)
				dd["pubkey"] = short(dd["pubkey"].(string), 1)
			},
			field: "deposit_data_pubkey",
		},
		{
			name: "short distributed public key",
			mutate: func(m map[string]any) {
				dv := dvJSON(m, 0)
				dv["distributed_public_key"] = short(dv["distributed_public_key"].(string), 1)
			},
			field: "distributed_public_key",
		},
		{
			name: "long public share",
			mutate: func(m map[string]any) {
				shares := dvJSON(m, 0)["public_shares"].([]any)
				shares[0] = long(shares[0].(string))
			},
			field: "public_shares",
		},
		{
			name: "short builder registration fee recipient",
			mutate: func(m map[string]any) {
				reg := dvJSON(m, 0)["builder_registration"].(map[string]any)["message"].(map[string]any)
				reg["fee_recipient"] = short(reg["fee_recipient"].(string), 1)
			},
			field: "builder_registration_fee_recipient",
		},
		{
			name: "short builder registration signature",
			mutate: func(m map[string]any) {
				reg := dvJSON(m, 1)["builder_registration"].(map[string]any)
				reg["signature"] = short(reg["signature"].(string), 1)
			},
			field: "builder_registration_signature",
		},
		{
			name:   "short lock hash",
			mutate: func(m map[string]any) { m["lock_hash"] = short(m["lock_hash"].(string), 1) },
			field:  "lock_hash",
		},
		{
			name: "short fork version",
			mutate: func(m map[string]any) {
				def := m["cluster_definition"].(map[string]any)
				def["fork_version"] = short(def["fork_version"].(string), 1)
			},
			field: "fork_version",
		},
		{
			name: "short config hash",
			mutate: func(m map[string]any) {
				def := m["cluster_definition"].(map[string]any)
				def["config_hash"] = short(def["config_hash"].(string), 1)
			},
			field: "config_hash",
		},
		{
			name: "long definition hash",
			mutate: func(m map[string]any) {
				def := m["cluster_definition"].(map[string]any)
				def["definition_hash"] = long(def["definition_hash"].(string))
			},
			field: "definition_hash",
		},
		{
			name: "short withdrawal address",
			mutate: func(m map[string]any) {
				vaddrs := m["cluster_definition"].(map[string]any)["validators"].([]any)[0].(map[string]any)
				vaddrs["withdrawal_address"] = short(vaddrs["withdrawal_address"].(string), 1)
			},
			field: "withdrawal_address",
		},
		{
			name: "long fee recipient address",
			mutate: func(m map[string]any) {
				vaddrs := m["cluster_definition"].(map[string]any)["validators"].([]any)[1].(map[string]any)
				vaddrs["fee_recipient_address"] = long(vaddrs["fee_recipient_address"].(string))
			},
			field: "fee_recipient_address",
		},
		{
			name: "short operator address",
			mutate: func(m map[string]any) {
				op := m["cluster_definition"].(map[string]any)["operators"].([]any)[0].(map[string]any)
				op["address"] = short(op["address"].(string), 1)
			},
			field: "operator_address",
		},
		{
			name: "short operator config signature",
			mutate: func(m map[string]any) {
				op := m["cluster_definition"].(map[string]any)["operators"].([]any)[0].(map[string]any)
				op["config_signature"] = short(op["config_signature"].(string), 1)
			},
			field: "operator_config_signature",
		},
		{
			name: "short creator config signature",
			mutate: func(m map[string]any) {
				creator := m["cluster_definition"].(map[string]any)["creator"].(map[string]any)
				creator["config_signature"] = short(creator["config_signature"].(string), 1)
			},
			field: "creator_config_signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m map[string]any
			require.NoError(t, json.Unmarshal(b, &m))

			tt.mutate(m)

			b2, err := json.Marshal(m)
			require.NoError(t, err)
			require.False(t, bytes.Equal(b, b2))

			var lock2 cluster.Lock

			err = json.Unmarshal(b2, &lock2)
			require.Error(t, err)
			require.True(t, z.ContainsField(err, z.Str("field", tt.field)), "missing field %s: %v", tt.field, err)
		})
	}

	t.Run("definition", func(t *testing.T) {
		var m map[string]any
		require.NoError(t, json.Unmarshal(b, &m))

		def := m["cluster_definition"].(map[string]any)
		def["fork_version"] = "0x000010"

		b2, err := json.Marshal(def)
		require.NoError(t, err)

		var def2 cluster.Definition

		err = json.Unmarshal(b2, &def2)
		require.ErrorContains(t, err, "invalid fixed size bytes length")
		require.True(t, z.ContainsField(err, z.Str("field", "fork_version")))
	})
}

func dvJSON(m map[string]any, dvIdx int) map[string]any {
	return m["distributed_validators"].([]any)[dvIdx].(map[string]any)
}

func depositJSON(m map[string]any, dvIdx, ddIdx int) map[string]any {
	return dvJSON(m, dvIdx)["partial_deposit_data"].([]any)[ddIdx].(map[string]any)
}

func TestVerifyLockRejectsInvalidSignatureLengths(t *testing.T) {
	lock, p2pKeys, shares := newLockWithDepositsForT(t, v1_11, false)

	short := lock
	short.SignatureAggregate = lock.SignatureAggregate[:95]
	require.ErrorContains(t, short.VerifySignatures(nil), "invalid lock aggregate signature length")

	short = lock
	short.NodeSignatures = [][]byte{lock.NodeSignatures[0][:64], lock.NodeSignatures[1], lock.NodeSignatures[2], lock.NodeSignatures[3]}
	require.ErrorContains(t, short.VerifySignatures(nil), "invalid node signature length")

	require.NoError(t, resignLockForT(t, lock, p2pKeys, shares).VerifySignatures(nil))
}

func TestVerifyLockRejectsMismatchingRegistration(t *testing.T) {
	lock, p2pKeys, shares := newLockWithDepositsForT(t, v1_11, false)

	tampered := lock
	tampered.Validators = append([]cluster.DistValidator(nil), lock.Validators...)
	tampered.Validators[0].BuilderRegistration.Message.FeeRecipient = bytes.Repeat([]byte{0x11}, 20)
	tampered = resignLockForT(t, tampered, p2pKeys, shares)
	require.ErrorContains(t, tampered.VerifySignatures(nil), "builder registration fee recipient doesn't match definition fee recipient")

	tampered = lock
	tampered.Validators = append([]cluster.DistValidator(nil), lock.Validators...)
	tampered.Validators[0].BuilderRegistration.Message.PubKey = lock.Validators[1].PubKey
	tampered = resignLockForT(t, tampered, p2pKeys, shares)
	require.ErrorContains(t, tampered.VerifySignatures(nil), "builder registration pubkey doesn't match distributed validator pubkey")
}

func TestVerifyDefinitionAddresses(t *testing.T) {
	lock, _, _ := newLockWithDepositsForT(t, v1_11, false)

	const checksummed = "0x52908400098527886E0F7030069857D2E4169EE7" // EIP-55 example.

	tests := []struct {
		name    string
		addr    string
		wantErr string
	}{
		{name: "checksummed", addr: checksummed},
		{name: "lower case", addr: strings.ToLower(checksummed)},
		{name: "upper case", addr: "0x" + strings.ToUpper(checksummed[2:])},
		{name: "bad checksum", addr: "0x52908400098527886e0F7030069857D2E4169EE7", wantErr: "invalid address checksum"},
		{name: "no 0x prefix", addr: checksummed[2:], wantErr: "invalid address"},
		{name: "empty", addr: "", wantErr: "missing address"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			def := lock.Definition
			def.ValidatorAddresses = append([]cluster.ValidatorAddresses(nil), def.ValidatorAddresses...)
			def.ValidatorAddresses[0].WithdrawalAddress = tt.addr

			err := def.VerifyHashes()
			if tt.wantErr == "" {
				// Only the hashes mismatch since the address changed.
				require.ErrorContains(t, err, "invalid config hash")
				return
			}

			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
