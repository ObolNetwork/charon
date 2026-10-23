// Copyright © 2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package specvectors_test runs the spec conformance suites that Charon's
// exported API can serve.
//
// The remaining suites exercise unexported functions (hashProto,
// verifyMsgLimits, calculateResult, verifyPeerShareIdx) and so live beside the
// code they test; specvectors.CoveredSuites records where each one is.
package specvectors_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil/specvectors"
)

func TestManifest(t *testing.T) {
	manifest := specvectors.LoadManifest(t)

	require.Equal(t, specvectors.PinnedSpecVersion, manifest.SpecVersion)
	require.NotEmpty(t, manifest.CharonAnchor.Commit)
	require.NotEmpty(t, manifest.TestVectors)
}

// TestEverySuiteIsCovered fails when a spec release adds a suite nothing runs.
// An uncovered suite is indistinguishable from a passing one, so bumping
// PinnedSpecVersion has to account for every suite the new release ships.
func TestEverySuiteIsCovered(t *testing.T) {
	for _, suite := range specvectors.LoadManifest(t).TestVectors {
		_, ok := specvectors.CoveredSuites[suite.Suite]
		require.Truef(t, ok, "spec suite %q is not covered by any Charon test; "+
			"add it to CoveredSuites with the test that runs it", suite.Suite)
		require.Positivef(t, suite.Cases, "suite %q ships no cases", suite.Suite)
	}
}

// --- cluster hashing --------------------------------------------------------

func TestClusterHashing(t *testing.T) {
	var suite struct {
		Definition []struct {
			Name           string          `json:"name"`
			Input          json.RawMessage `json:"input"`
			ConfigHash     string          `json:"config_hash"`
			DefinitionHash string          `json:"definition_hash"`
		} `json:"definition"`
		Lock []struct {
			Name     string          `json:"name"`
			Input    json.RawMessage `json:"input"`
			LockHash string          `json:"lock_hash"`
		} `json:"lock"`
	}
	specvectors.Load(t, "cluster_hashing", &suite)
	require.NotEmpty(t, suite.Definition)
	require.NotEmpty(t, suite.Lock)

	for _, tt := range suite.Definition {
		t.Run("definition/"+tt.Name, func(t *testing.T) {
			var definition cluster.Definition
			require.NoError(t, json.Unmarshal(tt.Input, &definition))

			hashed, err := definition.SetDefinitionHashes()
			require.NoError(t, err)

			require.Equal(t, tt.ConfigHash, hex.EncodeToString(hashed.ConfigHash))
			require.Equal(t, tt.DefinitionHash, hex.EncodeToString(hashed.DefinitionHash))
		})
	}

	for _, tt := range suite.Lock {
		t.Run("lock/"+tt.Name, func(t *testing.T) {
			var lock cluster.Lock
			require.NoError(t, json.Unmarshal(tt.Input, &lock))

			hashed, err := lock.SetLockHash()
			require.NoError(t, err)

			require.Equal(t, tt.LockHash, hex.EncodeToString(hashed.LockHash))
		})
	}
}

// --- cluster validation ------------------------------------------------------

// TestClusterValidation runs the accept/reject verdicts of cluster_validation.
//
// A definition is accepted if it unmarshals and its stored hashes verify; a lock
// if it unmarshals and passes VerifyHashes and VerifySignatures (no eth1 client
// is needed: every lock case has an unsigned definition). Only the verdict is
// asserted. The suite's reason slugs name the spec rule that fired, and Charon's
// error text is not mapped onto them.
//
// Charon releases up to the anchor accept most rejected cases: they pad short
// fixed-size fields, ignore address case, and do not check lock deposit data or
// zero addresses at load. The cases are built so that every hash and signature
// in them verifies for a reader that pads, so passing this test needs the
// field rules themselves.
func TestClusterValidation(t *testing.T) {
	type validationCase struct {
		Name     string          `json:"name"`
		Input    json.RawMessage `json:"input"`
		Accepted bool            `json:"accepted"`
		Reason   *string         `json:"reason"`
	}

	var suite struct {
		Definition []validationCase `json:"definition"`
		Lock       []validationCase `json:"lock"`
	}
	specvectors.Load(t, "cluster_validation", &suite)
	require.NotEmpty(t, suite.Definition)
	require.NotEmpty(t, suite.Lock)

	verdict := func(t *testing.T, tt validationCase, err error) {
		t.Helper()

		if tt.Accepted {
			require.NoError(t, err)
			return
		}

		require.Errorf(t, err, "must reject: %s", *tt.Reason)
	}

	for _, tt := range suite.Definition {
		t.Run("definition/"+tt.Name, func(t *testing.T) {
			var definition cluster.Definition

			err := json.Unmarshal(tt.Input, &definition)
			if err == nil {
				err = definition.VerifyHashes()
			}

			verdict(t, tt, err)
		})
	}

	for _, tt := range suite.Lock {
		t.Run("lock/"+tt.Name, func(t *testing.T) {
			var lock cluster.Lock

			err := json.Unmarshal(tt.Input, &lock)
			if err == nil {
				err = lock.VerifyHashes()
			}

			if err == nil {
				err = lock.VerifySignatures(nil)
			}

			verdict(t, tt, err)
		})
	}
}

// --- BLS threshold signatures ----------------------------------------------

type shareIndices struct {
	ShareIndices []int `json:"share_indices"`
}

func TestBLSThreshold(t *testing.T) {
	var suite struct {
		MessageHex        string `json:"message_hex"`
		GroupSecretHex    string `json:"group_secret_hex"`
		GroupPubkeyHex    string `json:"group_pubkey_hex"`
		GroupSignatureHex string `json:"group_signature_hex"`
		Keys              []struct {
			Name  string `json:"name"`
			Input struct {
				SecretHex string `json:"secret_hex"`
			} `json:"input"`
			PubkeyHex string `json:"pubkey_hex"`
		} `json:"keys"`
		Partials []struct {
			Name  string `json:"name"`
			Input struct {
				ShareIdx  int    `json:"share_idx"`
				SecretHex string `json:"secret_hex"`
			} `json:"input"`
			PubshareHex  string `json:"pubshare_hex"`
			SignatureHex string `json:"signature_hex"`
		} `json:"partials"`
		ThresholdAggregates []struct {
			Name         string       `json:"name"`
			Input        shareIndices `json:"input"`
			SignatureHex string       `json:"signature_hex"`
		} `json:"threshold_aggregates"`
		Recovery []struct {
			Name      string       `json:"name"`
			Input     shareIndices `json:"input"`
			PubkeyHex string       `json:"pubkey_hex"`
		} `json:"recovery"`
		PlainAggregate []struct {
			Name         string       `json:"name"`
			Input        shareIndices `json:"input"`
			SignatureHex string       `json:"signature_hex"`
		} `json:"plain_aggregate"`
	}
	specvectors.Load(t, "bls_threshold", &suite)

	message := specvectors.HexToBytes(t, suite.MessageHex)

	t.Run("group_key_and_signature", func(t *testing.T) {
		secret := blsPrivkey(t, suite.GroupSecretHex)

		pubkey, err := tbls.SecretToPublicKey(secret)
		require.NoError(t, err)
		require.Equal(t, suite.GroupPubkeyHex, hex.EncodeToString(pubkey[:]))

		// Charon's BLS signing is deterministic, so exact bytes are pinnable.
		sig, err := tbls.Sign(secret, message)
		require.NoError(t, err)
		require.Equal(t, suite.GroupSignatureHex, hex.EncodeToString(sig[:]))
	})

	for _, tt := range suite.Keys {
		t.Run("keys/"+tt.Name, func(t *testing.T) {
			pubkey, err := tbls.SecretToPublicKey(blsPrivkey(t, tt.Input.SecretHex))
			require.NoError(t, err)
			require.Equal(t, tt.PubkeyHex, hex.EncodeToString(pubkey[:]))
		})
	}

	partialSigs := make(map[int]tbls.Signature)
	pubshares := make(map[int]tbls.PublicKey)

	for _, tt := range suite.Partials {
		t.Run("partials/"+tt.Name, func(t *testing.T) {
			secret := blsPrivkey(t, tt.Input.SecretHex)

			pubshare, err := tbls.SecretToPublicKey(secret)
			require.NoError(t, err)
			require.Equal(t, tt.PubshareHex, hex.EncodeToString(pubshare[:]))

			sig, err := tbls.Sign(secret, message)
			require.NoError(t, err)
			require.Equal(t, tt.SignatureHex, hex.EncodeToString(sig[:]))
		})

		partialSigs[tt.Input.ShareIdx] = blsSignature(t, tt.SignatureHex)
		pubshares[tt.Input.ShareIdx] = blsPubkey(t, tt.PubshareHex)
	}

	groupPubkey := blsPubkey(t, suite.GroupPubkeyHex)

	// The point of the suite: every quorum must reconstruct the same group
	// signature. One quorum proves nothing, since wrong Lagrange coefficients
	// still yield a well-formed signature.
	for _, tt := range suite.ThresholdAggregates {
		t.Run("threshold_aggregates/"+tt.Name, func(t *testing.T) {
			aggregate, err := tbls.ThresholdAggregate(pick(t, partialSigs, tt.Input.ShareIndices))
			require.NoError(t, err)
			require.Equal(t, tt.SignatureHex, hex.EncodeToString(aggregate[:]))
			require.NoError(t, tbls.Verify(groupPubkey, message, aggregate))
		})
	}

	for _, tt := range suite.Recovery {
		t.Run("recovery/"+tt.Name, func(t *testing.T) {
			recovered, err := tbls.RecoverPubkey(pick(t, pubshares, tt.Input.ShareIndices))
			require.NoError(t, err)
			require.Equal(t, tt.PubkeyHex, hex.EncodeToString(recovered[:]))
		})
	}

	// Plain aggregation is a different operation, used for the lock hash
	// multi-signature. Pinning that it does *not* verify under the group key is
	// what stops an implementation using it where threshold aggregation belongs.
	for _, tt := range suite.PlainAggregate {
		t.Run("plain_aggregate/"+tt.Name, func(t *testing.T) {
			var sigs []tbls.Signature

			for _, idx := range tt.Input.ShareIndices {
				sig, ok := partialSigs[idx]
				require.Truef(t, ok, "no partial for share index %d", idx)

				sigs = append(sigs, sig)
			}

			aggregate, err := tbls.Aggregate(sigs)
			require.NoError(t, err)
			require.Equal(t, tt.SignatureHex, hex.EncodeToString(aggregate[:]))
			require.Error(t, tbls.Verify(groupPubkey, message, aggregate))
		})
	}
}

// --- secp256k1 node signatures ---------------------------------------------

func TestSecp256k1Signatures(t *testing.T) {
	var suite struct {
		SecretHex string `json:"secret_hex"`
		PubkeyHex string `json:"pubkey_hex"`
		Cases     []struct {
			Name  string `json:"name"`
			Input struct {
				HashHex string `json:"hash_hex"`
			} `json:"input"`
			SignatureHex       string `json:"signature_hex"`
			RecoveredPubkeyHex string `json:"recovered_pubkey_hex"`
		} `json:"cases"`
	}
	specvectors.Load(t, "secp256k1_signatures", &suite)
	require.NotEmpty(t, suite.Cases)

	key := k1.PrivKeyFromBytes(specvectors.HexToBytes(t, suite.SecretHex))
	require.Equal(t, suite.PubkeyHex, hex.EncodeToString(key.PubKey().SerializeCompressed()))

	for _, tt := range suite.Cases {
		t.Run(tt.Name, func(t *testing.T) {
			hash := specvectors.HexToBytes(t, tt.Input.HashHex)

			// RFC 6979 makes k1 signing deterministic, so exact bytes are pinnable.
			sig, err := k1util.Sign(key, hash)
			require.NoError(t, err)
			require.Equal(t, tt.SignatureHex, hex.EncodeToString(sig))

			recovered, err := k1util.Recover(hash, specvectors.HexToBytes(t, tt.SignatureHex))
			require.NoError(t, err)
			require.Equal(t, tt.RecoveredPubkeyHex,
				hex.EncodeToString(recovered.SerializeCompressed()))
		})
	}
}

// --- helpers ----------------------------------------------------------------

// pick selects the entries a case names, failing if the suite references an
// index it never defined.
func pick[T any](tb testing.TB, all map[int]T, indices []int) map[int]T {
	tb.Helper()

	picked := make(map[int]T, len(indices))
	for _, idx := range indices {
		value, ok := all[idx]
		require.Truef(tb, ok, "suite references share index %d with no entry", idx)
		picked[idx] = value
	}

	return picked
}

func blsPrivkey(tb testing.TB, s string) tbls.PrivateKey {
	tb.Helper()

	var key tbls.PrivateKey
	copyExact(tb, key[:], s)

	return key
}

func blsPubkey(tb testing.TB, s string) tbls.PublicKey {
	tb.Helper()

	var key tbls.PublicKey
	copyExact(tb, key[:], s)

	return key
}

func blsSignature(tb testing.TB, s string) tbls.Signature {
	tb.Helper()

	var sig tbls.Signature
	copyExact(tb, sig[:], s)

	return sig
}

// copyExact decodes hex into a fixed-size destination, failing on a length
// mismatch rather than silently truncating or zero-padding.
func copyExact(tb testing.TB, dst []byte, s string) {
	tb.Helper()

	decoded := specvectors.HexToBytes(tb, s)
	require.Lenf(tb, decoded, len(dst), "expected %d bytes, vector has %d", len(dst), len(decoded))
	copy(dst, decoded)
}
