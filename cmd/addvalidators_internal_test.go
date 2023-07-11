// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/cluster"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
	"github.com/obolnetwork/charon/testutil"
)

const (
	feeRecipientAddr = "0x0000000000000000000000000000000000000000"
)

func TestValidateConfigAddValidators(t *testing.T) {
	tests := []struct {
		name   string
		conf   addValidatorsConfig
		numOps int
		errMsg string
	}{
		{
			name: "insufficient validators",
			conf: addValidatorsConfig{
				NumVals: 0,
			},
			errMsg: "insufficient validator count",
		},
		{
			name: "empty fee recipient addrs",
			conf: addValidatorsConfig{
				NumVals:           1,
				FeeRecipientAddrs: nil,
			},
			errMsg: "empty fee recipient addresses",
		},
		{
			name: "empty withdrawal addrs",
			conf: addValidatorsConfig{
				NumVals:           1,
				WithdrawalAddrs:   nil,
				FeeRecipientAddrs: []string{feeRecipientAddr},
			},
			errMsg: "empty withdrawal addresses",
		},
		{
			name: "addrs length mismatch",
			conf: addValidatorsConfig{
				NumVals:           1,
				WithdrawalAddrs:   []string{feeRecipientAddr, feeRecipientAddr},
				FeeRecipientAddrs: []string{feeRecipientAddr},
			},
			errMsg: "fee recipient and withdrawal addresses lengths mismatch",
		},
		{
			name: "single addr for all validators",
			conf: addValidatorsConfig{
				NumVals:           2,
				WithdrawalAddrs:   []string{feeRecipientAddr},
				FeeRecipientAddrs: []string{feeRecipientAddr},
			},
		},
		{
			name: "count and addrs mismatch",
			conf: addValidatorsConfig{
				NumVals:           2,
				WithdrawalAddrs:   []string{feeRecipientAddr, feeRecipientAddr, feeRecipientAddr},
				FeeRecipientAddrs: []string{feeRecipientAddr, feeRecipientAddr, feeRecipientAddr},
			},
			errMsg: "count of validators and addresses mismatch",
		},
		{
			name: "multiple addrs for multiple validators",
			conf: addValidatorsConfig{
				NumVals:           2,
				WithdrawalAddrs:   []string{feeRecipientAddr, feeRecipientAddr},
				FeeRecipientAddrs: []string{feeRecipientAddr, feeRecipientAddr},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConf(tt.conf)
			if tt.errMsg != "" {
				require.Equal(t, tt.errMsg, err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TODO(xenowits): Add more extensive tests, this is just a very simple unit test.
func TestRunAddValidators(t *testing.T) {
	const (
		n        = 3
		valCount = 1
	)

	var nodeDirnames []string
	for i := 0; i < n; i++ {
		nodeDirnames = append(nodeDirnames, fmt.Sprintf("node%d", i))
	}

	t.Run("add validators once", func(t *testing.T) {
		lock, p2pKeys, _ := cluster.NewForT(t, valCount, n, n, 0)

		tmp := t.TempDir()
		for _, dirname := range nodeDirnames {
			dir := path.Join(tmp, dirname)
			require.NoError(t, os.Mkdir(dir, 0o777))
			require.NoError(t, os.Mkdir(path.Join(dir, "validator_keys"), 0o777))
		}

		conf := addValidatorsConfig{
			NumVals:           1,
			WithdrawalAddrs:   []string{feeRecipientAddr},
			FeeRecipientAddrs: []string{feeRecipientAddr},
			TestConfig: TestConfig{
				Lock:    &lock,
				P2PKeys: p2pKeys,
			},
			ClusterDir: tmp,
		}

		err := runAddValidatorsSolo(context.Background(), conf)
		require.NoError(t, err)

		// Verify the new cluster manifest
		b, err := os.ReadFile(path.Join(tmp, "node0", "cluster-manifest.pb"))
		require.NoError(t, err)

		var msg manifestpb.Cluster
		require.NoError(t, proto.Unmarshal(b, &msg))
		require.Equal(t, valCount+1, len(msg.Validators))
		require.Equal(t, msg.Validators[1].FeeRecipientAddress, feeRecipientAddr)
		require.Equal(t, msg.Validators[1].WithdrawalAddress, feeRecipientAddr)
	})

	t.Run("add validators twice", func(t *testing.T) {
		lock, p2pKeys, _ := cluster.NewForT(t, valCount, n, n, 0)

		tmp := t.TempDir()
		for _, dirname := range nodeDirnames {
			dir := path.Join(tmp, dirname)
			require.NoError(t, os.Mkdir(dir, 0o777))
			require.NoError(t, os.Mkdir(path.Join(dir, "validator_keys"), 0o777))
		}

		conf := addValidatorsConfig{
			NumVals:           1,
			WithdrawalAddrs:   []string{feeRecipientAddr},
			FeeRecipientAddrs: []string{feeRecipientAddr},
			TestConfig: TestConfig{
				Lock:    &lock,
				P2PKeys: p2pKeys,
			},
			ClusterDir: tmp,
		}

		// First add one validator
		require.NoError(t, runAddValidatorsSolo(context.Background(), conf))

		manifestFile := path.Join(tmp, "node0", "cluster-manifest.pb")
		b, err := os.ReadFile(manifestFile)
		require.NoError(t, err)
		cluster := new(manifestpb.Cluster)
		require.NoError(t, proto.Unmarshal(b, cluster))
		require.Equal(t, cluster.InitialMutationHash, lock.LockHash)

		// Run the second add validators command using cluster manifest output from the first run
		conf.TestConfig.Lock = nil
		conf.TestConfig.Manifest = cluster
		// Delete existing deposit data file in each node directory since the deposit file names are same
		// when add validators command is run twice consecutively. This is because the test finishes in
		// milliseconds and filenames are named YYYYMMDDHHMMSS which doesn't account for milliseconds.
		for i := 0; i < n; i++ {
			entries, err := os.ReadDir(nodeDir(tmp, i))
			require.NoError(t, err)
			for _, e := range entries {
				if strings.Contains(e.Name(), "deposit-data") {
					require.NoError(t, os.Remove(path.Join(nodeDir(tmp, i), e.Name())))
				}
			}
		}

		// Then add the second validator
		require.NoError(t, runAddValidatorsSolo(context.Background(), conf))

		b, err = os.ReadFile(manifestFile)
		require.NoError(t, err)
		cluster = new(manifestpb.Cluster)
		require.NoError(t, proto.Unmarshal(b, cluster))

		// The cluster manifest should contain three validators now since the
		// original cluster already had one validator, and we added two more.
		require.Equal(t, valCount+2, len(cluster.Validators))
		require.Equal(t, cluster.InitialMutationHash, lock.LockHash)

		entries, err := os.ReadDir(path.Join(tmp, "node0"))
		require.NoError(t, err)
		require.Equal(t, 3, len(entries))

		require.True(t, strings.Contains(entries[0].Name(), "cluster-manifest"))
		require.True(t, strings.Contains(entries[1].Name(), "deposit-data"))
		require.True(t, strings.Contains(entries[2].Name(), "validator_keys"))
	})
}

func TestValidateP2PKeysOrder(t *testing.T) {
	const (
		seed = 123
		n    = 4
	)

	t.Run("correct order", func(t *testing.T) {
		var (
			p2pKeys []*k1.PrivateKey
			ops     []*manifestpb.Operator
		)

		for i := 0; i < n; i++ {
			key, enrStr := testutil.RandomENR(t, seed+i)
			p2pKeys = append(p2pKeys, key)
			ops = append(ops, &manifestpb.Operator{Enr: enrStr.String()})
		}

		err := validateP2PKeysOrder(p2pKeys, ops)
		require.NoError(t, err)
	})

	t.Run("length mismatch", func(t *testing.T) {
		key, _ := testutil.RandomENR(t, seed)
		err := validateP2PKeysOrder([]*k1.PrivateKey{key}, nil)
		require.ErrorContains(t, err, "length of p2p keys and enrs don't match")
	})

	t.Run("invalid order", func(t *testing.T) {
		var (
			p2pKeys []*k1.PrivateKey
			ops     []*manifestpb.Operator
		)

		for i := 0; i < n; i++ {
			key, enrStr := testutil.RandomENR(t, seed+i)
			p2pKeys = append(p2pKeys, key)
			ops = append(ops, &manifestpb.Operator{Enr: enrStr.String()})
		}

		// Swap first and last elements of p2p keys list
		first := p2pKeys[0]
		last := p2pKeys[n-1]
		p2pKeys[0] = last
		p2pKeys[n-1] = first

		err := validateP2PKeysOrder(p2pKeys, ops)
		require.ErrorContains(t, err, "invalid p2p key order")
	})
}
