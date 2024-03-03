// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"fmt"
	"math/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
	"github.com/obolnetwork/charon/testutil/obolapimock"
)

const badStr = "bad"

func Test_runBcastFullExitCmd(t *testing.T) {
	t.Parallel()
	t.Run("main flow", Test_runBcastFullExitCmdFlow)
	t.Run("config", Test_runBcastFullExitCmd_Config)
}

func Test_runBcastFullExitCmdFlow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	valAmt := 100
	operatorAmt := 4

	random := rand.New(rand.NewSource(int64(0)))

	lock, enrs, keyShares := cluster.NewForT(
		t,
		valAmt,
		operatorAmt,
		operatorAmt,
		0,
		random,
	)

	root := t.TempDir()

	operatorShares := make([][]tbls.PrivateKey, operatorAmt)

	for opIdx := 0; opIdx < operatorAmt; opIdx++ {
		for _, share := range keyShares {
			operatorShares[opIdx] = append(operatorShares[opIdx], share[opIdx])
		}
	}

	dag, err := manifest.NewDAGFromLockForT(t, lock)
	require.NoError(t, err)

	mBytes, err := proto.Marshal(dag)
	require.NoError(t, err)

	handler, addLockFiles := obolapimock.MockServer(false)
	srv := httptest.NewServer(handler)
	addLockFiles(lock)
	defer srv.Close()

	validatorSet := beaconmock.ValidatorSet{}

	for idx, v := range lock.Validators {
		validatorSet[eth2p0.ValidatorIndex(idx)] = &eth2v1.Validator{
			Index:   eth2p0.ValidatorIndex(idx),
			Balance: 42,
			Status:  eth2v1.ValidatorStateActiveOngoing,
			Validator: &eth2p0.Validator{
				PublicKey:             eth2p0.BLSPubKey(v.PubKey),
				WithdrawalCredentials: testutil.RandomBytes32(),
			},
		}
	}

	beaconMock, err := beaconmock.New(
		beaconmock.WithValidatorSet(validatorSet),
		beaconmock.WithEndpoint("/eth/v1/beacon/pool/voluntary_exits", ""),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, beaconMock.Close())
	}()

	writeAllLockData(t, root, operatorAmt, enrs, operatorShares, mBytes)

	for idx := 0; idx < operatorAmt; idx++ {
		config := exitConfig{
			BeaconNodeURL:   beaconMock.Address(),
			ValidatorAddr:   lock.Validators[0].PublicKeyHex(),
			DataDir:         filepath.Join(root, fmt.Sprintf("op%d", idx)),
			ObolAPIEndpoint: srv.URL,
			ExitEpoch:       194048,
		}

		require.NoError(t, runSubmitPartialExit(ctx, config), "operator index: %v", idx)
	}

	config := exitConfig{
		BeaconNodeURL:   beaconMock.Address(),
		ValidatorAddr:   lock.Validators[0].PublicKeyHex(),
		DataDir:         filepath.Join(root, fmt.Sprintf("op%d", 0)),
		ObolAPIEndpoint: srv.URL,
		ExitEpoch:       194048,
	}

	require.NoError(t, runBcastFullExit(ctx, config))
}

func Test_runBcastFullExitCmd_Config(t *testing.T) {
	t.Parallel()
	type test struct {
		name             string
		noIdentity       bool
		noManifest       bool
		badOAPIURL       bool
		badBeaconNodeURL bool
		badValidatorAddr bool
		errData          string
	}

	tests := []test{
		{
			name:       "No identity key",
			noIdentity: true,
			errData:    "could not load identity key",
		},
		{
			name:       "No manifest",
			noManifest: true,
			errData:    "could not load cluster data",
		},
		{
			name:       "Bad Obol API URL",
			badOAPIURL: true,
			errData:    "could not create obol api client",
		},
		{
			name:             "Bad beacon node URL",
			badBeaconNodeURL: true,
			errData:          "cannot create eth2 client for specified beacon node",
		},
		{
			name:             "Bad validator address",
			badValidatorAddr: true,
			errData:          "cannot convert validator pubkey to bytes",
		},
	}

	del := func(t *testing.T, tc test, root string, opIdx int) {
		t.Helper()

		opID := fmt.Sprintf("op%d", opIdx)
		oDir := filepath.Join(root, opID)

		switch {
		case tc.noManifest:
			require.NoError(t, os.RemoveAll(filepath.Join(oDir, "cluster-manifest.pb")))
		case tc.noIdentity:
			require.NoError(t, os.RemoveAll(filepath.Join(oDir, "charon-enr-private-key")))
		}
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			valAmt := 100
			operatorAmt := 4

			random := rand.New(rand.NewSource(int64(0)))

			lock, enrs, keyShares := cluster.NewForT(
				t,
				valAmt,
				operatorAmt,
				operatorAmt,
				0,
				random,
			)

			root := t.TempDir()

			operatorShares := make([][]tbls.PrivateKey, operatorAmt)

			for opIdx := 0; opIdx < operatorAmt; opIdx++ {
				for _, share := range keyShares {
					operatorShares[opIdx] = append(operatorShares[opIdx], share[opIdx])
				}
			}

			dag, err := manifest.NewDAGFromLockForT(t, lock)
			require.NoError(t, err)

			mBytes, err := proto.Marshal(dag)
			require.NoError(t, err)

			writeAllLockData(t, root, operatorAmt, enrs, operatorShares, mBytes)

			for opIdx := 0; opIdx < operatorAmt; opIdx++ {
				del(t, test, root, opIdx)
			}

			bnURL := badStr

			if !test.badBeaconNodeURL {
				beaconMock, err := beaconmock.New()
				require.NoError(t, err)
				defer func() {
					require.NoError(t, beaconMock.Close())
				}()
				bnURL = beaconMock.Address()
			}

			oapiURL := badStr
			if !test.badOAPIURL {
				oapiURL = "https://api.obol.tech"
			}

			valAddr := badStr
			if !test.badValidatorAddr {
				valAddr = lock.Validators[0].PublicKeyHex()
			}

			config := exitConfig{
				BeaconNodeURL:   bnURL,
				ValidatorAddr:   valAddr,
				DataDir:         filepath.Join(root, "op0"), // one operator is enough
				ObolAPIEndpoint: oapiURL,
				ExitEpoch:       0,
			}

			require.ErrorContains(t, runBcastFullExit(ctx, config), test.errData)
		})
	}
}
