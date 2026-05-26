// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
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

	_, err = cl.GetFullDeposit(t.Context(), lock.Validators[0].PublicKeyHex(), lock.LockHash, lock.Threshold, lock.Validators[0].PubShares, network)
	require.NoError(t, err, "full deposit")
}

// depositFixture builds a 3-of-5 cluster, signs a full set of partial deposit signatures, and
// assembles a baseline FullDepositResponse. Negative-path tests tamper one field of the returned
// response before serving it from a canned httptest.Server.
type depositFixture struct {
	lock     cluster.Lock
	network  string
	response obolapi.FullDepositResponse
}

func newDepositFixture(t *testing.T) depositFixture {
	t.Helper()

	const (
		numNodes  = 5
		threshold = 3
	)

	random := rand.New(rand.NewSource(int64(0)))

	lock, _, shares := cluster.NewForT(t, 1, threshold, numNodes, 0, random)

	wc, err := hex.DecodeString("010000000000000000000000000000000000000000000000000000000000dead")
	require.NoError(t, err)

	depositMsg := eth2p0.DepositMessage{
		PublicKey:             eth2p0.BLSPubKey(lock.Validators[0].PubKey),
		WithdrawalCredentials: wc,
		Amount:                eth2p0.Gwei(deposit.OneEthInGwei * 32),
	}

	network, err := eth2util.ForkVersionToNetwork(lock.ForkVersion)
	require.NoError(t, err)

	sigRoot, err := deposit.GetMessageSigningRoot(depositMsg, network)
	require.NoError(t, err)

	partials := make([]obolapi.Partial, 0, numNodes)

	for shareIdx, share := range shares[0] {
		sig, err := tbls.Sign(share, sigRoot[:])
		require.NoError(t, err)

		partials = append(partials, obolapi.Partial{
			PartialPublicKey:        "0x" + hex.EncodeToString(lock.Validators[0].PubShares[shareIdx]),
			PartialDepositSignature: fmt.Sprintf("%#x", sig[:]),
		})
	}

	return depositFixture{
		lock:    lock,
		network: network,
		response: obolapi.FullDepositResponse{
			PublicKey:             lock.Validators[0].PublicKeyHex(),
			WithdrawalCredentials: "0x" + hex.EncodeToString(wc),
			Amounts: []obolapi.Amount{{
				Amount:   strconv.FormatUint(uint64(depositMsg.Amount), 10),
				Partials: partials,
			}},
		},
	}
}

// serveCannedDeposit starts an httptest.Server that always returns the provided response JSON.
func serveCannedDeposit(t *testing.T, resp obolapi.FullDepositResponse) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	t.Cleanup(srv.Close)

	return srv
}

func TestGetFullDeposit_MissingPartialPubkey(t *testing.T) {
	f := newDepositFixture(t)
	f.response.Amounts[0].Partials[1].PartialPublicKey = ""

	srv := serveCannedDeposit(t, f.response)

	cl, err := obolapi.New(srv.URL)
	require.NoError(t, err)

	_, err = cl.GetFullDeposit(t.Context(), f.lock.Validators[0].PublicKeyHex(), f.lock.LockHash, f.lock.Threshold, f.lock.Validators[0].PubShares, f.network)
	require.ErrorContains(t, err, "partial public key missing from Obol API response")
}

func TestGetFullDeposit_UnknownPartialPubkey(t *testing.T) {
	f := newDepositFixture(t)
	// Replace with a syntactically valid 48-byte pubkey that isn't one of the validator's shares.
	f.response.Amounts[0].Partials[1].PartialPublicKey = "0x" + hex.EncodeToString(make([]byte, 48))

	srv := serveCannedDeposit(t, f.response)

	cl, err := obolapi.New(srv.URL)
	require.NoError(t, err)

	_, err = cl.GetFullDeposit(t.Context(), f.lock.Validators[0].PublicKeyHex(), f.lock.LockHash, f.lock.Threshold, f.lock.Validators[0].PubShares, f.network)
	require.ErrorContains(t, err, "partial public key not found in validator public shares")
}

func TestGetFullDeposit_TamperedPartialSignature(t *testing.T) {
	f := newDepositFixture(t)
	// Swap signatures of shares 1 and 2: each is valid in isolation, but no longer matches its claimed share.
	f.response.Amounts[0].Partials[0].PartialDepositSignature, f.response.Amounts[0].Partials[1].PartialDepositSignature = f.response.Amounts[0].Partials[1].PartialDepositSignature, f.response.Amounts[0].Partials[0].PartialDepositSignature

	srv := serveCannedDeposit(t, f.response)

	cl, err := obolapi.New(srv.URL)
	require.NoError(t, err)

	_, err = cl.GetFullDeposit(t.Context(), f.lock.Validators[0].PublicKeyHex(), f.lock.LockHash, f.lock.Threshold, f.lock.Validators[0].PubShares, f.network)
	require.ErrorContains(t, err, "partial deposit signature failed BLS verification")
}

func TestGetFullDeposit_DuplicateShareIndex(t *testing.T) {
	f := newDepositFixture(t)
	// Make two entries claim the same share: copy partial[0] over partial[1].
	f.response.Amounts[0].Partials[1] = f.response.Amounts[0].Partials[0]

	srv := serveCannedDeposit(t, f.response)

	cl, err := obolapi.New(srv.URL)
	require.NoError(t, err)

	_, err = cl.GetFullDeposit(t.Context(), f.lock.Validators[0].PublicKeyHex(), f.lock.LockHash, f.lock.Threshold, f.lock.Validators[0].PubShares, f.network)
	require.ErrorContains(t, err, "duplicate partial signature for share index")
}

func TestGetFullDeposit_NotEnoughSignatures(t *testing.T) {
	f := newDepositFixture(t)
	// Blank out enough partial signatures to drop below threshold (3 of 5 → blank 3).
	for i := range 3 {
		f.response.Amounts[0].Partials[i].PartialDepositSignature = ""
	}

	srv := serveCannedDeposit(t, f.response)

	cl, err := obolapi.New(srv.URL)
	require.NoError(t, err)

	_, err = cl.GetFullDeposit(t.Context(), f.lock.Validators[0].PublicKeyHex(), f.lock.LockHash, f.lock.Threshold, f.lock.Validators[0].PubShares, f.network)
	require.ErrorContains(t, err, "not enough partial signatures to meet threshold")
}
