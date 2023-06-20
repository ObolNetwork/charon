// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
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
	enrPrivKeyFile   = ".charon/charon-enr-private-key"
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
			name: "insufficient enr private key files",
			conf: addValidatorsConfig{
				NumVals:           1,
				WithdrawalAddrs:   []string{feeRecipientAddr},
				FeeRecipientAddrs: []string{feeRecipientAddr},
				EnrPrivKeyfiles:   []string{enrPrivKeyFile},
			},
			numOps: 2,
			errMsg: "insufficient enr private key files",
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
			err := validateConf(tt.conf, tt.numOps)
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
	lock, p2pKeys, _ := cluster.NewForT(t, valCount, n, n, 0)

	tmp := t.TempDir()
	manifestFile := path.Join(tmp, "cluster-manifest.pb")
	backupDir := path.Join(tmp, "cluster-backups")

	conf := addValidatorsConfig{
		NumVals:           1,
		WithdrawalAddrs:   []string{feeRecipientAddr},
		FeeRecipientAddrs: []string{feeRecipientAddr},
		TestConfig: TestConfig{
			Lock:    &lock,
			P2PKeys: p2pKeys,
		},
		ClusterManifestFile: manifestFile,
		ClusterBackupDir:    backupDir,
	}

	err := runAddValidatorsSolo(context.Background(), conf)
	require.NoError(t, err)

	// Verify the new cluster manifest
	b, err := os.ReadFile(manifestFile)
	require.NoError(t, err)

	var msg manifestpb.Cluster
	require.NoError(t, proto.Unmarshal(b, &msg))
	require.Equal(t, len(msg.Validators), 2) // valCount+1
	require.Equal(t, msg.Validators[1].FeeRecipientAddress, feeRecipientAddr)

	// Verify the backup cluster manifest
	entries, err := os.ReadDir(backupDir)
	require.NoError(t, err)
	require.Equal(t, 1, len(entries))
	require.True(t, strings.Contains(entries[0].Name(), "cluster-manifest-backup"))

	backupFile := path.Join(backupDir, entries[0].Name())
	b, err = os.ReadFile(backupFile)
	require.NoError(t, err)

	// Verify if new validator is included in updated cluster manifest
	var msgBackup manifestpb.Cluster
	require.NoError(t, proto.Unmarshal(b, &msgBackup))
	require.Equal(t, len(msgBackup.Validators), valCount)
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

func TestWriteClusterBackup(t *testing.T) {
	t.Run("dir is a file", func(t *testing.T) {
		file := path.Join(t.TempDir(), "clusters")
		_, err := os.Create(file)
		require.NoError(t, err)

		err = writeClusterBackup(file, &manifestpb.Cluster{})
		require.ErrorContains(t, err, "backup dir already exists and is a file")
	})

	t.Run("dir already exists", func(t *testing.T) {
		dir := t.TempDir()
		clusterName := "Test#001"
		err := writeClusterBackup(dir, &manifestpb.Cluster{Name: clusterName})
		require.NoError(t, err)

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Equal(t, 1, len(entries))
		require.True(t, strings.Contains(entries[0].Name(), "cluster-manifest-backup"))

		b, err := os.ReadFile(path.Join(dir, entries[0].Name()))
		require.NoError(t, err)

		var msg manifestpb.Cluster
		require.NoError(t, proto.Unmarshal(b, &msg))
		require.Equal(t, clusterName, msg.Name)
	})

	t.Run("create backup dir", func(t *testing.T) {
		err := writeClusterBackup("", &manifestpb.Cluster{})
		require.ErrorContains(t, err, "create backup dir")
	})
}
