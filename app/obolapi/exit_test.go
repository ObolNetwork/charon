// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi_test

import (
	"context"
	"math/rand"
	"net/http/httptest"
	"testing"
	"time"

	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil/beaconmock"
	"github.com/obolnetwork/charon/testutil/obolapimock"
)

const exitEpoch = eth2p0.Epoch(194048)

func TestAPIExit(t *testing.T) {
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

	lock, identityKeys, shares := cluster.NewForT(
		t,
		1,
		kn,
		kn,
		0,
		random,
	)

	addLockFiles(lock)

	exitMsg := eth2p0.SignedVoluntaryExit{
		Message: &eth2p0.VoluntaryExit{
			Epoch:          42,
			ValidatorIndex: 42,
		},
		Signature: eth2p0.BLSSignature{},
	}

	sigRoot, err := exitMsg.Message.HashTreeRoot()
	require.NoError(t, err)

	domain, err := signing.GetDomain(context.Background(), mockEth2Cl, signing.DomainExit, exitEpoch)
	require.NoError(t, err)

	sigData, err := (&eth2p0.SigningData{ObjectRoot: sigRoot, Domain: domain}).HashTreeRoot()
	require.NoError(t, err)

	for idx := range len(shares) {
		var exits []obolapi.ExitBlob

		for _, shareSet := range shares[idx] {
			signature, err := tbls.Sign(shareSet, sigData[:])
			require.NoError(t, err)

			exitMsg := exitMsg
			exitMsg.Signature = eth2p0.BLSSignature(signature)

			exit := obolapi.ExitBlob{
				PublicKey:         lock.Validators[0].PublicKeyHex(),
				SignedExitMessage: exitMsg,
			}

			exits = append(exits, exit)
		}

		cl, err := obolapi.New(srv.URL)
		require.NoError(t, err)

		ctx := context.Background()

		// send all the partial exits
		for idx, exit := range exits {
			require.NoError(t, cl.PostPartialExits(ctx, lock.LockHash, uint64(idx+1), identityKeys[idx], exit), "share index: %d", idx+1)
		}

		for idx := range exits {
			// get full exit
			fullExit, err := cl.GetFullExit(ctx, lock.Validators[0].PublicKeyHex(), lock.LockHash, uint64(idx+1), identityKeys[idx], lock.Validators[0].PubShares, mockEth2Cl)
			require.NoError(t, err, "share index: %d", idx+1)

			valPubk, err := lock.Validators[0].PublicKey()
			require.NoError(t, err, "share index: %d", idx+1)

			sig, err := tblsconv.SignatureFromBytes(fullExit.SignedExitMessage.Signature[:])
			require.NoError(t, err, "share index: %d", idx+1)

			// verify that the aggregated signature works
			require.NoError(t, tbls.Verify(valPubk, sigData[:], sig), "share index: %d", idx+1)
		}
	}
}

func TestAPIExitMissingSig(t *testing.T) {
	kn := 4

	beaconMock, err := beaconmock.New(t.Context())
	require.NoError(t, err)

	defer func() {
		require.NoError(t, beaconMock.Close())
	}()

	mockEth2Cl := eth2Client(t, context.Background(), beaconMock.Address())

	handler, addLockFiles := obolapimock.MockServer(true, mockEth2Cl)
	srv := httptest.NewServer(handler)

	defer srv.Close()

	random := rand.New(rand.NewSource(int64(0)))

	lock, identityKeys, shares := cluster.NewForT(
		t,
		1,
		kn-1,
		kn,
		0,
		random,
	)

	addLockFiles(lock)

	exitMsg := eth2p0.SignedVoluntaryExit{
		Message: &eth2p0.VoluntaryExit{
			Epoch:          42,
			ValidatorIndex: 42,
		},
		Signature: eth2p0.BLSSignature{},
	}

	sigRoot, err := exitMsg.Message.HashTreeRoot()
	require.NoError(t, err)

	domain, err := signing.GetDomain(context.Background(), mockEth2Cl, signing.DomainExit, exitEpoch)
	require.NoError(t, err)

	sigData, err := (&eth2p0.SigningData{ObjectRoot: sigRoot, Domain: domain}).HashTreeRoot()
	require.NoError(t, err)

	for idx := range len(shares) {
		var exits []obolapi.ExitBlob

		for _, shareSet := range shares[idx] {
			signature, err := tbls.Sign(shareSet, sigData[:])
			require.NoError(t, err)

			exitMsg := exitMsg
			exitMsg.Signature = eth2p0.BLSSignature(signature)

			exit := obolapi.ExitBlob{
				PublicKey:         lock.Validators[0].PublicKeyHex(),
				SignedExitMessage: exitMsg,
			}

			exits = append(exits, exit)
		}

		cl, err := obolapi.New(srv.URL)
		require.NoError(t, err)

		ctx := context.Background()

		// send all the partial exits
		for idx, exit := range exits {
			require.NoError(t, cl.PostPartialExits(ctx, lock.LockHash, uint64(idx+1), identityKeys[idx], exit), "share index: %d", idx+1)
		}

		for idx := range exits {
			// get full exit
			fullExit, err := cl.GetFullExit(ctx, lock.Validators[0].PublicKeyHex(), lock.LockHash, uint64(idx+1), identityKeys[idx], lock.Validators[0].PubShares, mockEth2Cl)
			require.NoError(t, err, "share index: %d", idx+1)

			valPubk, err := lock.Validators[0].PublicKey()
			require.NoError(t, err, "share index: %d", idx+1)

			sig, err := tblsconv.SignatureFromBytes(fullExit.SignedExitMessage.Signature[:])
			require.NoError(t, err, "share index: %d", idx+1)

			// verify that the aggregated signature works
			require.NoError(t, tbls.Verify(valPubk, sigData[:], sig), "share index: %d", idx+1)
		}
	}
}

// TestAPIExitNonContiguousShares demonstrates a vulnerability where GetFullExit
// remaps partial-signature shares by slice position instead of by their true
// share index. When the submitting subset is non-contiguous and excludes share
// index 1 (e.g. shares 2, 3, 4 in a 3-of-4 cluster), the compact list returned
// by the API gets reassigned to indices 1, 2, 3 inside ThresholdAggregate, so
// Lagrange interpolation uses wrong x-coordinates and the aggregated signature
// fails BLS verification.
func TestAPIExitNonContiguousShares(t *testing.T) {
	kn := 4
	threshold := 3

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

	lock, identityKeys, shares := cluster.NewForT(
		t,
		1,
		threshold,
		kn,
		0,
		random,
	)

	addLockFiles(lock)

	exitMsg := eth2p0.SignedVoluntaryExit{
		Message: &eth2p0.VoluntaryExit{
			Epoch:          42,
			ValidatorIndex: 42,
		},
		Signature: eth2p0.BLSSignature{},
	}

	sigRoot, err := exitMsg.Message.HashTreeRoot()
	require.NoError(t, err)

	domain, err := signing.GetDomain(context.Background(), mockEth2Cl, signing.DomainExit, exitEpoch)
	require.NoError(t, err)

	sigData, err := (&eth2p0.SigningData{ObjectRoot: sigRoot, Domain: domain}).HashTreeRoot()
	require.NoError(t, err)

	// Build partial exits per operator (shares[0] is the only validator's shares).
	var exits []obolapi.ExitBlob

	for _, shareSet := range shares[0] {
		signature, err := tbls.Sign(shareSet, sigData[:])
		require.NoError(t, err)

		em := exitMsg
		em.Signature = eth2p0.BLSSignature(signature)

		exits = append(exits, obolapi.ExitBlob{
			PublicKey:         lock.Validators[0].PublicKeyHex(),
			SignedExitMessage: em,
		})
	}

	cl, err := obolapi.New(srv.URL)
	require.NoError(t, err)

	ctx := context.Background()

	// Only submit partials from share indices 2, 3, 4 — skip share index 1.
	// The threshold (3) is still met, so the API will return a full exit.
	for idx := 1; idx < kn; idx++ {
		shareIdx := uint64(idx + 1)
		require.NoError(t, cl.PostPartialExits(ctx, lock.LockHash, shareIdx, identityKeys[idx], exits[idx]),
			"share index: %d", shareIdx)
	}

	fullExit, err := cl.GetFullExit(ctx, lock.Validators[0].PublicKeyHex(), lock.LockHash, 2, identityKeys[1], lock.Validators[0].PubShares, mockEth2Cl)
	require.NoError(t, err)

	valPubk, err := lock.Validators[0].PublicKey()
	require.NoError(t, err)

	sig, err := tblsconv.SignatureFromBytes(fullExit.SignedExitMessage.Signature[:])
	require.NoError(t, err)

	// Bug: the aggregated signature fails BLS verification because GetFullExit
	// remapped shares {2,3,4} to indices {1,2,3} during ThresholdAggregate.
	require.NoError(t, tbls.Verify(valPubk, sigData[:], sig),
		"aggregated signature must verify against the validator's group public key")
}

func eth2Client(t *testing.T, ctx context.Context, bnURL string) eth2wrap.Client {
	t.Helper()

	bnHTTPClient, err := eth2http.New(ctx,
		eth2http.WithAddress(bnURL),
		eth2http.WithLogLevel(zerolog.InfoLevel),
	)

	require.NoError(t, err)

	bnClient := bnHTTPClient.(*eth2http.Service)

	return eth2wrap.AdaptEth2HTTP(bnClient, nil, 1*time.Second)
}
