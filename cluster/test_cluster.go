// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	crand "crypto/rand"
	"io"
	"math/rand"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/eth2util/registration"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
)

// NewForT returns a new cluster lock with dv number of distributed validators, k threshold and n peers.
// It also returns the peer p2p keys and BLS secret shares. If the seed is zero a random cluster on available loopback
// ports is generated, else a deterministic cluster is generated.
// Note this is not defined in testutil since it is tightly coupled with the cluster package.
func NewForT(t *testing.T, dv, k, n, seed int, opts ...func(*Definition)) (Lock, []*k1.PrivateKey, [][]tbls.PrivateKey) {
	t.Helper()

	var (
		vals     []DistValidator
		p2pKeys  []*k1.PrivateKey
		ops      []Operator
		dvShares [][]tbls.PrivateKey
	)

	random := io.Reader(rand.New(rand.NewSource(int64(seed)))) //nolint:gosec // Explicit use of weak random generator for determinism.
	if seed == 0 {
		random = crand.Reader
	} else {
		rand.Seed(int64(seed))
	}

	var feeRecipientAddrs, withdrawalAddrs []string
	for i := 0; i < dv; i++ {
		rootSecret, err := tbls.GenerateInsecureKey(t, random)
		require.NoError(t, err)

		rootPublic, err := tbls.SecretToPublicKey(rootSecret)
		require.NoError(t, err)

		shares, err := tbls.ThresholdSplitInsecure(t, rootSecret, uint(n), uint(k), random)
		require.NoError(t, err)

		var pubshares [][]byte
		var privshares []tbls.PrivateKey
		for i := 0; i < n; i++ {
			sharePrivkey := shares[i+1] // Share indexes are 1-indexed.

			sharePub, err := tbls.SecretToPublicKey(sharePrivkey)
			require.NoError(t, err)

			pubshares = append(pubshares, sharePub[:])

			privshares = append(privshares, sharePrivkey)
		}

		feeRecipientAddr := testutil.RandomETHAddress()
		reg := getSignedRegistration(t, rootSecret, feeRecipientAddr, eth2util.Goerli.Name)

		vals = append(vals, DistValidator{
			PubKey:              rootPublic[:],
			PubShares:           pubshares,
			BuilderRegistration: reg,
		})
		dvShares = append(dvShares, privshares)
		feeRecipientAddrs = append(feeRecipientAddrs, feeRecipientAddr)
		withdrawalAddrs = append(withdrawalAddrs, testutil.RandomETHAddress())
	}

	for i := 0; i < n; i++ {
		// Generate ENR
		p2pKey := testutil.GenerateInsecureK1Key(t, seed+i)

		record, err := enr.New(p2pKey)
		require.NoError(t, err)

		addr := eth2util.PublicKeyToAddress(p2pKey.PubKey())
		op := Operator{
			Address: addr,
			ENR:     record.String(),
			// Set to empty signatures instead of nil so aligned with unmarshalled json
			ENRSignature:    ethHex{},
			ConfigSignature: ethHex{},
		}

		ops = append(ops, op)
		p2pKeys = append(p2pKeys, p2pKey)
	}

	// Use operator 0 as the creator.
	creator := Creator{Address: ops[0].Address}

	def, err := NewDefinition("test cluster", dv, k,
		feeRecipientAddrs, withdrawalAddrs,
		eth2util.Goerli.GenesisForkVersionHex, creator, ops, random, opts...)
	require.NoError(t, err)

	// Definition version prior to v1.3.0 don't support EIP712 signatures.
	if supportEIP712Sigs(def.Version) {
		for i := 0; i < n; i++ {
			def.Operators[i], err = signOperator(p2pKeys[i], def, def.Operators[i])
			require.NoError(t, err)
		}

		def, err = signCreator(p2pKeys[0], def)
		require.NoError(t, err)

		// Recalculate definition hash after adding signatures.
		def, err = def.SetDefinitionHashes()
		require.NoError(t, err)
	}

	lock := Lock{
		Definition:         def,
		Validators:         vals,
		SignatureAggregate: nil,
	}

	lock, err = lock.SetLockHash()
	require.NoError(t, err)

	lock.SignatureAggregate, err = aggSign(dvShares, lock.LockHash)
	require.NoError(t, err)

	for _, p2pKey := range p2pKeys {
		nodeSig, err := k1util.Sign(p2pKey, lock.LockHash)
		require.NoError(t, err)

		lock.NodeSignatures = append(lock.NodeSignatures, nodeSig)
	}

	// Clear node signatures if before v1.7
	if isAnyVersion(lock.Version, v1_0, v1_1, v1_2, v1_3, v1_4, v1_5, v1_6) {
		lock.NodeSignatures = nil
	}

	return lock, p2pKeys, dvShares
}

func getSignedRegistration(t *testing.T, secret tbls.PrivateKey, feeRecipientAddr string, network string) BuilderRegistration {
	t.Helper()

	timestamp, err := eth2util.NetworkToGenesisTime(network)
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	eth2pubkey, err := tblsconv.PubkeyToETH2(pubkey)
	require.NoError(t, err)

	msg, err := registration.NewMessage(eth2pubkey, feeRecipientAddr, registration.DefaultGasLimit, timestamp)
	require.NoError(t, err)

	forkVersion, err := eth2util.NetworkToForkVersionBytes(network)
	require.NoError(t, err)

	require.Len(t, forkVersion, 4)

	sigRoot, err := registration.GetMessageSigningRoot(msg, eth2p0.Version(forkVersion))
	require.NoError(t, err)

	sig, err := tbls.Sign(secret, sigRoot[:])
	require.NoError(t, err)

	return BuilderRegistration{
		Message: Registration{
			FeeRecipient: msg.FeeRecipient[:],
			GasLimit:     int(msg.GasLimit),
			Timestamp:    msg.Timestamp,
			PubKey:       msg.Pubkey[:],
		},
		Signature: sig[:],
	}
}

// RandomRegistration returns a random builder registration.
func RandomRegistration(t *testing.T, network string) BuilderRegistration {
	t.Helper()

	timestamp, err := eth2util.NetworkToGenesisTime(network)
	require.NoError(t, err)

	return BuilderRegistration{
		Message: Registration{
			FeeRecipient: testutil.RandomBytes32()[:20],
			GasLimit:     30000000,
			Timestamp:    timestamp,
			PubKey:       testutil.RandomBytes48(),
		},
		Signature: testutil.RandomBytes96(),
	}
}
