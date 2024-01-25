// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
)

func TestInvalidSignatures(t *testing.T) {
	const (
		n  = 4
		th = 3
	)

	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	secretShares, err := tbls.ThresholdSplit(secret, n, th)
	require.NoError(t, err)

	pubshares := make(map[int]tbls.PublicKey)

	for idx, share := range secretShares {
		pubkey, err := tbls.SecretToPublicKey(share)
		require.NoError(t, err)

		pubshares[idx] = pubkey
	}

	shares := share{
		PubKey:       pubkey,
		SecretShare:  secretShares[0],
		PublicShares: pubshares,
	}

	getSigs := func(msg []byte) []core.ParSignedData {
		var sigs []core.ParSignedData
		for i := 0; i < n-1; i++ {
			sig, err := tbls.Sign(secretShares[i+1], msg)
			require.NoError(t, err)

			sigs = append(sigs, core.NewPartialSignature(tblsconv.SigToCore(sig), i+1))
		}

		invalidSig, err := tbls.Sign(secretShares[n-1], []byte("invalid msg"))
		require.NoError(t, err)

		sigs = append(sigs, core.NewPartialSignature(tblsconv.SigToCore(invalidSig), n))

		return sigs
	}

	corePubkey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)

	// Aggregate and verify deposit data signatures
	msg := testutil.RandomDepositMsg(t)

	_, err = aggDepositData(
		map[core.PubKey][]core.ParSignedData{corePubkey: getSigs([]byte("any digest"))},
		[]share{shares},
		map[core.PubKey]eth2p0.DepositMessage{corePubkey: msg},
		eth2util.Goerli.Name,
	)
	require.EqualError(t, err, "invalid deposit data partial signature from peer")

	// Aggregate and verify cluster lock hash signatures
	lockMsg := []byte("cluster lock hash")

	_, _, err = aggLockHashSig(map[core.PubKey][]core.ParSignedData{corePubkey: getSigs(lockMsg)}, map[core.PubKey]share{corePubkey: shares}, lockMsg)
	require.EqualError(t, err, "invalid lock hash partial signature from peer: signature not verified")
}

func TestValidSignatures(t *testing.T) {
	const (
		n  = 4
		th = 3
	)

	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	secretShares, err := tbls.ThresholdSplit(secret, n, th)
	require.NoError(t, err)

	pubshares := make(map[int]tbls.PublicKey)

	for idx, share := range secretShares {
		pubkey, err := tbls.SecretToPublicKey(share)
		require.NoError(t, err)

		pubshares[idx] = pubkey
	}

	shares := share{
		PubKey:       pubkey,
		SecretShare:  secret,
		PublicShares: pubshares,
	}

	getSigs := func(msg []byte) []core.ParSignedData {
		var sigs []core.ParSignedData
		for i := 0; i < n-1; i++ {
			pk := secretShares[i+1]
			sig, err := tbls.Sign(pk, msg)
			require.NoError(t, err)

			coreSig := tblsconv.SigToCore(sig)
			sigs = append(sigs, core.NewPartialSignature(coreSig, i+1))
		}

		return sigs
	}

	corePubkey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	eth2Pubkey, err := corePubkey.ToETH2()
	require.NoError(t, err)

	withdrawalAddr := testutil.RandomETHAddress()
	network := eth2util.Goerli.Name

	msg, err := deposit.NewMessage(eth2Pubkey, withdrawalAddr, deposit.MaxValidatorAmount)
	require.NoError(t, err)
	sigRoot, err := deposit.GetMessageSigningRoot(msg, network)
	require.NoError(t, err)

	_, err = aggDepositData(
		map[core.PubKey][]core.ParSignedData{corePubkey: getSigs(sigRoot[:])},
		[]share{shares},
		map[core.PubKey]eth2p0.DepositMessage{corePubkey: msg},
		network,
	)
	require.NoError(t, err)

	// Aggregate and verify cluster lock hash signatures
	lockMsg := []byte("cluster lock hash")

	_, _, err = aggLockHashSig(map[core.PubKey][]core.ParSignedData{corePubkey: getSigs(lockMsg)}, map[core.PubKey]share{corePubkey: shares}, lockMsg)
	require.NoError(t, err)
}

func TestValidateKeymanagerFlags(t *testing.T) {
	tests := []struct {
		name      string
		addr      string
		authToken string
		errMsg    string
	}{
		{
			name:      "Both keymanager flags provided",
			addr:      "https://keymanager@example.com",
			authToken: "keymanager-auth-token",
			errMsg:    "",
		},
		{
			name:   "Address provided but auth token absent",
			addr:   "https://keymanager@example.com",
			errMsg: "--keymanager-address provided but --keymanager-auth-token absent. Please fix configuration flags",
		},
		{
			name:      "Auth token provided by address absent",
			authToken: "keymanager-auth-token",
			errMsg:    "--keymanager-auth-token provided but --keymanager-address absent. Please fix configuration flags",
		},
		{
			name:      "Malformed address provided",
			addr:      "https://keymanager@example.com:-80",
			authToken: "keymanager-auth-token",
			errMsg:    "failed to parse keymanager addr",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKeymanagerFlags(context.Background(), tt.addr, tt.authToken)
			if tt.errMsg != "" {
				require.ErrorContains(t, err, tt.errMsg)
			}
		})
	}
}
