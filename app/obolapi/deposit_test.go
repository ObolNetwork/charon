// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	// Use a 3-of-5 cluster and submit from non-contiguous nodes (2, 4, 5) to
	// exercise correct share-index mapping in ThresholdAggregate.
	const (
		numNodes  = 5
		threshold = 3
	)

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

	lock, _, shares := cluster.NewForT(
		t,
		1,
		threshold,
		numNodes,
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

	// Submit from nodes 2, 4, 5 (0-indexed: 1, 3, 4) — non-contiguous share indices.
	for _, idx := range []int{1, 3, 4} {
		shareIndex := uint64(idx + 1)

		signature, err := tbls.Sign(shares[0][idx], depositMessageSigRoot[:])
		require.NoError(t, err)

		depositData := eth2p0.DepositData{
			PublicKey:             depositMessage.PublicKey,
			WithdrawalCredentials: depositMessage.WithdrawalCredentials,
			Amount:                depositMessage.Amount,
			Signature:             eth2p0.BLSSignature(signature),
		}

		require.NoError(t, cl.PostPartialDeposits(t.Context(), lock.LockHash, shareIndex, []eth2p0.DepositData{depositData}), "share index: %d", shareIndex)
	}

	_, err = cl.GetFullDeposit(t.Context(), lock.Validators[0].PublicKeyHex(), lock.LockHash, lock.Threshold, lock.Validators[0].PubShares)
	require.NoError(t, err, "full deposit")
}
