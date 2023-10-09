// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package combine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
	"github.com/obolnetwork/charon/cmd/combine"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
)

func noLockModif(_ int, l cluster.Lock) cluster.Lock {
	return l
}

func TestCombineNoLockfile(t *testing.T) {
	td := t.TempDir()
	od := t.TempDir()
	err := combine.Combine(context.Background(), td, od, false, false)
	require.ErrorContains(t, err, "no manifest file found")
}

func TestCombineCannotLoadKeystore(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 2, 3, 4, 0)

	for _, share := range shares {
		share := share

		sm := make(map[int]tbls.PrivateKey)
		for idx, shareObj := range share {
			shareObj := shareObj
			sm[idx+1] = shareObj
		}
	}

	dir := t.TempDir()
	od := t.TempDir()

	// flatten secrets, each validator slice is unpacked in a flat structure
	var rawSecrets []tbls.PrivateKey
	for _, s := range shares {
		rawSecrets = append(rawSecrets, s...)
	}

	// for each ENR, create a slice of keys to hold
	// each set will be len(lock.Definition.Operators)
	secrets := make([][]tbls.PrivateKey, len(lock.Definition.Operators))

	// populate key sets
	for enrIdx := 0; enrIdx < len(lock.Definition.Operators); enrIdx++ {
		keyIdx := enrIdx
		for dvIdx := 0; dvIdx < lock.NumValidators; dvIdx++ {
			secrets[enrIdx] = append(secrets[enrIdx], rawSecrets[keyIdx])
			keyIdx += len(lock.Definition.Operators)
		}
	}

	for idx, keys := range secrets {
		ep := filepath.Join(dir, fmt.Sprintf("node%d", idx))

		vk := filepath.Join(ep, "validator_keys")

		require.NoError(t, os.Mkdir(ep, 0o755))
		require.NoError(t, os.Mkdir(vk, 0o755))
		require.NoError(t, keystore.StoreKeysInsecure(keys, vk, keystore.ConfirmInsecureKeys))

		lf, err := os.OpenFile(filepath.Join(ep, "cluster-lock.json"), os.O_WRONLY|os.O_CREATE, 0o755)
		require.NoError(t, err)

		require.NoError(t, json.NewEncoder(lf).Encode(lock))
	}

	require.NoError(t, os.RemoveAll(filepath.Join(dir, "node0")))

	err := combine.Combine(context.Background(), dir, od, false, false, combine.WithInsecureKeysForT(t))
	require.Error(t, err)
}

func TestCombineAllManifest(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 100, 3, 4, 0)
	combineTest(t, lock, shares, false, false, noLockModif, []manifestChoice{
		ManifestOnly,
		ManifestOnly,
		ManifestOnly,
		ManifestOnly,
	})
}

func TestCombineBothManifestAndLockForAll(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 100, 3, 4, 0)
	combineTest(t, lock, shares, false, false, noLockModif, []manifestChoice{
		Both,
		Both,
		Both,
		Both,
	})
}

func TestCombineBothManifestAndLockForSome(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 100, 3, 4, 0)
	combineTest(t, lock, shares, false, false, noLockModif, []manifestChoice{
		ManifestOnly,
		Both,
		Both,
		LockOnly,
	})
}

// This test exists because of https://github.com/ObolNetwork/charon/issues/2151.
func TestCombineLotsOfVals(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 100, 3, 4, 0)
	combineTest(t, lock, shares, false, false, noLockModif, nil)
}

func TestCombine(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 2, 3, 4, 0)
	combineTest(t, lock, shares, false, false, noLockModif, nil)
}

func TestCombineNoVerifyGoodLock(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 2, 3, 4, 0)
	combineTest(t, lock, shares, true, false, noLockModif, nil)
}

func TestCombineNoVerifyBadLock(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 2, 3, 4, 0)
	combineTest(t, lock, shares, true, false, func(valIndex int, src cluster.Lock) cluster.Lock {
		if valIndex == 1 {
			src.Name = "booohooo"
		}

		return src
	}, nil)
}

func TestCombineBadLock(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 2, 3, 4, 0)
	combineTest(t, lock, shares, false, true, func(valIndex int, src cluster.Lock) cluster.Lock {
		if valIndex == 1 {
			src.Name = "booohooo"
		}

		return src
	}, nil)
}

func TestCombineNoVerifyDifferentValidatorData(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 2, 3, 4, 0)
	combineTest(t, lock, shares, true, true, func(valIndex int, src cluster.Lock) cluster.Lock {
		if valIndex == 1 {
			src.Validators[valIndex].PubKey = bytes.Repeat([]byte{42}, 48)
		}

		return src
	}, nil)
}

type manifestChoice int

const (
	ManifestOnly manifestChoice = iota
	LockOnly
	Both
)

func writeManifest(
	t *testing.T,
	valIdx int,
	modifyLockFile func(valIndex int, src cluster.Lock) cluster.Lock,
	path string,
	lock cluster.Lock,
) {
	t.Helper()
	legacy, err := manifest.NewLegacyLockForT(t, modifyLockFile(valIdx, lock))
	require.NoError(t, err)

	dag := &manifestpb.SignedMutationList{Mutations: []*manifestpb.SignedMutation{legacy}}
	data, err := proto.Marshal(dag)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(path, "cluster-manifest.pb"), data, 0o755))
}

func writeLock(
	t *testing.T,
	valIdx int,
	modifyLockFile func(valIndex int, src cluster.Lock) cluster.Lock,
	path string,
	lock cluster.Lock,
) {
	t.Helper()
	lf, err := os.OpenFile(filepath.Join(path, "cluster-lock.json"), os.O_WRONLY|os.O_CREATE, 0o755)
	require.NoError(t, err)

	require.NoError(t, json.NewEncoder(lf).Encode(modifyLockFile(valIdx, lock)))
}

func combineTest(
	t *testing.T,
	lock cluster.Lock,
	shares [][]tbls.PrivateKey,
	noVerify bool,
	wantErr bool,
	modifyLockFile func(valIndex int, src cluster.Lock) cluster.Lock,
	manifestOrLock []manifestChoice,
) {
	t.Helper()

	// calculate expected public keys and secrets
	type expected struct {
		pubkey string
		secret string
	}

	var expectedData []expected

	for _, share := range shares {
		share := share

		sm := make(map[int]tbls.PrivateKey)
		for idx, shareObj := range share {
			shareObj := shareObj
			sm[idx+1] = shareObj
		}

		complSecret, err := tbls.RecoverSecret(sm, 4, 3)
		require.NoError(t, err)

		complPubkey, err := tbls.SecretToPublicKey(complSecret)
		require.NoError(t, err)

		expectedData = append(expectedData, expected{
			pubkey: fmt.Sprintf("%#x", complPubkey),
			secret: fmt.Sprintf("%#x", complSecret),
		})
	}

	dir := t.TempDir()
	od := path.Join(dir, "validator_keys")

	// flatten secrets, each validator slice is unpacked in a flat structure
	var rawSecrets []tbls.PrivateKey
	for _, s := range shares {
		rawSecrets = append(rawSecrets, s...)
	}

	// for each ENR, create a slice of keys to hold
	// each set will be len(lock.Definition.Operators)
	secrets := make([][]tbls.PrivateKey, len(lock.Definition.Operators))

	// populate key sets
	for enrIdx := 0; enrIdx < len(lock.Definition.Operators); enrIdx++ {
		keyIdx := enrIdx
		for dvIdx := 0; dvIdx < lock.NumValidators; dvIdx++ {
			secrets[enrIdx] = append(secrets[enrIdx], rawSecrets[keyIdx])
			keyIdx += len(lock.Definition.Operators)
		}
	}

	for idx, keys := range secrets {
		idx := idx
		ep := filepath.Join(dir, fmt.Sprintf("node%d", idx))

		vk := filepath.Join(ep, "validator_keys")

		require.NoError(t, os.Mkdir(ep, 0o755))
		require.NoError(t, os.Mkdir(vk, 0o755))
		require.NoError(t, keystore.StoreKeysInsecure(keys, vk, keystore.ConfirmInsecureKeys))

		if len(manifestOrLock) == 0 {
			// default to lockfile
			writeLock(t, idx, modifyLockFile, ep, lock)
			continue
		}

		switch manifestOrLock[idx] {
		case ManifestOnly:
			writeManifest(t, idx, modifyLockFile, ep, lock)
		case LockOnly:
			writeLock(t, idx, modifyLockFile, ep, lock)
		case Both:
			writeManifest(t, idx, modifyLockFile, ep, lock)
			writeLock(t, idx, modifyLockFile, ep, lock)
		}
	}

	err := combine.Combine(context.Background(), dir, od, true, noVerify, combine.WithInsecureKeysForT(t))
	if wantErr {
		require.Error(t, err)
		return
	}

	require.NoError(t, err)

	keyFiles, err := keystore.LoadFilesUnordered(od)
	require.NoError(t, err)

	keysMap := make(map[string]string)
	for _, keyFile := range keyFiles {
		pk, err := tbls.SecretToPublicKey(keyFile.PrivateKey)
		require.NoError(t, err)

		keysMap[fmt.Sprintf("%#x", pk)] = fmt.Sprintf("%#x", keyFile.PrivateKey)
	}

	for _, exp := range expectedData {
		require.Contains(t, keysMap, exp.pubkey)
		require.Equal(t, exp.secret, keysMap[exp.pubkey])
	}

	require.Len(t, keysMap, len(expectedData))
}

func TestCombineTwiceWithoutForceFails(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 2, 3, 4, 0)

	// calculate expected public keys and secrets
	type expected struct {
		pubkey string
		secret string
	}

	var expectedData []expected

	for _, share := range shares {
		share := share

		sm := make(map[int]tbls.PrivateKey)
		for idx, shareObj := range share {
			shareObj := shareObj
			sm[idx+1] = shareObj
		}

		complSecret, err := tbls.RecoverSecret(sm, 4, 3)
		require.NoError(t, err)

		complPubkey, err := tbls.SecretToPublicKey(complSecret)
		require.NoError(t, err)

		expectedData = append(expectedData, expected{
			pubkey: fmt.Sprintf("%#x", complPubkey),
			secret: fmt.Sprintf("%#x", complSecret),
		})
	}

	dir := t.TempDir()
	od := t.TempDir()

	// flatten secrets, each validator slice is unpacked in a flat structure
	var rawSecrets []tbls.PrivateKey
	for _, s := range shares {
		rawSecrets = append(rawSecrets, s...)
	}

	// for each ENR, create a slice of keys to hold
	// each set will be len(lock.Definition.Operators)
	secrets := make([][]tbls.PrivateKey, len(lock.Definition.Operators))

	// populate key sets
	for enrIdx := 0; enrIdx < len(lock.Definition.Operators); enrIdx++ {
		keyIdx := enrIdx
		for dvIdx := 0; dvIdx < lock.NumValidators; dvIdx++ {
			secrets[enrIdx] = append(secrets[enrIdx], rawSecrets[keyIdx])
			keyIdx += len(lock.Definition.Operators)
		}
	}

	for idx, keys := range secrets {
		ep := filepath.Join(dir, fmt.Sprintf("node%d", idx))

		vk := filepath.Join(ep, "validator_keys")

		require.NoError(t, os.Mkdir(ep, 0o755))
		require.NoError(t, os.Mkdir(vk, 0o755))
		require.NoError(t, keystore.StoreKeysInsecure(keys, vk, keystore.ConfirmInsecureKeys))

		lf, err := os.OpenFile(filepath.Join(ep, "cluster-lock.json"), os.O_WRONLY|os.O_CREATE, 0o755)
		require.NoError(t, err)

		require.NoError(t, json.NewEncoder(lf).Encode(lock))
	}

	err := combine.Combine(context.Background(), dir, od, false, false, combine.WithInsecureKeysForT(t))
	require.NoError(t, err)

	err = combine.Combine(context.Background(), dir, od, false, false, combine.WithInsecureKeysForT(t))
	require.Error(t, err)

	keyFiles, err := keystore.LoadFilesUnordered(od)
	require.NoError(t, err)

	keysMap := make(map[string]string)
	for _, keyFile := range keyFiles {
		pk, err := tbls.SecretToPublicKey(keyFile.PrivateKey)
		require.NoError(t, err)

		keysMap[fmt.Sprintf("%#x", pk)] = fmt.Sprintf("%#x", keyFile.PrivateKey)
	}

	for _, exp := range expectedData {
		require.Contains(t, keysMap, exp.pubkey)
		require.Equal(t, exp.secret, keysMap[exp.pubkey])
	}

	require.Len(t, keysMap, len(expectedData))
}
