// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi_test

import (
	"context"
	"encoding/hex"
	"math/rand"
	"net/http/httptest"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil/beaconmock"
	"github.com/obolnetwork/charon/testutil/obolapimock"
)

func TestAPIDeposit(t *testing.T) {
	kn := 4

	beaconMock, err := beaconmock.New(t.Context())
	require.NoError(t, err)

	defer func() {
		require.NoError(t, beaconMock.Close())
	}()

	mockEth2Cl := eth2Client(t, context.Background(), beaconMock.Address())

	handler, addLockFiles := obolapimock.MockServer(false, mockEth2Cl)
	srv := httptest.NewServer(handler)

	defer srv.Close()

	random := rand.New(rand.NewSource(int64(0)))

	lock, peers, shares := cluster.NewForT(
		t,
		1,
		kn,
		kn,
		0,
		random,
	)

	addLockFiles(lock)

	wc, err := hex.DecodeString("010000000000000000000000000000000000000000000000000000000000dead")
	require.NoError(t, err)

	depositMessage := eth2p0.DepositMessage{
		PublicKey:             eth2p0.BLSPubKey(lock.Validators[0].PubKey),
		WithdrawalCredentials: wc,
		Amount:                eth2p0.Gwei(deposit.OneEthInGwei * 32),
	}

	network, err := eth2util.ForkVersionToNetwork(lock.ForkVersion)
	require.NoError(t, err)

	depositMessageSigRoot, err := deposit.GetMessageSigningRoot(depositMessage, network)
	require.NoError(t, err)

	cl, err := obolapi.New(srv.URL)
	require.NoError(t, err)

	for idx := range len(peers) {
		signature, err := tbls.Sign(shares[0][idx], depositMessageSigRoot[:])
		require.NoError(t, err)

		depositData := eth2p0.DepositData{
			PublicKey:             depositMessage.PublicKey,
			WithdrawalCredentials: depositMessage.WithdrawalCredentials,
			Amount:                depositMessage.Amount,
			Signature:             eth2p0.BLSSignature(signature),
		}

		// send all the partial deposits
		require.NoError(t, cl.PostPartialDeposits(t.Context(), lock.LockHash, uint64(idx+1), []eth2p0.DepositData{depositData}), "share index: %d", idx+1)
	}

	// get full exit
	_, err = cl.GetFullDeposit(t.Context(), lock.Validators[0].PublicKeyHex(), lock.LockHash, lock.Threshold)
	require.NoError(t, err, "full deposit")
}
