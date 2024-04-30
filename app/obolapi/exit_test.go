// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

const exitEpoch = eth2p0.Epoch(162304)

func TestAPIFlow(t *testing.T) {
	kn := 4

	beaconMock, err := beaconmock.New()
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

	for idx := 0; idx < len(shares); idx++ {
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
			require.NoError(t, cl.PostPartialExit(ctx, lock.LockHash, uint64(idx+1), identityKeys[idx], exit), "share index: %d", idx+1)
		}

		for idx := range exits {
			// get full exit
			fullExit, err := cl.GetFullExit(ctx, lock.Validators[0].PublicKeyHex(), lock.LockHash, uint64(idx+1), identityKeys[idx])
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

func TestAPIFlowMissingSig(t *testing.T) {
	kn := 4

	beaconMock, err := beaconmock.New()
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

	for idx := 0; idx < len(shares); idx++ {
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
			require.NoError(t, cl.PostPartialExit(ctx, lock.LockHash, uint64(idx+1), identityKeys[idx], exit), "share index: %d", idx+1)
		}

		for idx := range exits {
			// get full exit
			fullExit, err := cl.GetFullExit(ctx, lock.Validators[0].PublicKeyHex(), lock.LockHash, uint64(idx+1), identityKeys[idx])
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

func eth2Client(t *testing.T, ctx context.Context, bnURL string) eth2wrap.Client {
	t.Helper()

	bnHTTPClient, err := eth2http.New(ctx,
		eth2http.WithAddress(bnURL),
		eth2http.WithLogLevel(zerolog.InfoLevel),
	)

	require.NoError(t, err)

	bnClient := bnHTTPClient.(*eth2http.Service)

	return eth2wrap.AdaptEth2HTTP(bnClient, 1*time.Second)
}
