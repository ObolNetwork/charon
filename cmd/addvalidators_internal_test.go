// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/state"
	"github.com/obolnetwork/charon/testutil"
)

const (
	feeRecipientAddr = "0x0000000000000000000000000000000000000000"
	enrPrivKeyFile   = ".charon/charon-enr-private-key"
)

func TestValidateConfigAddValidators(t *testing.T) {
	_, record := testutil.RandomENR(t, 1)
	op := state.Operator{
		Address: testutil.RandomETHAddress(),
		ENR:     record.String(),
	}

	tests := []struct {
		name      string
		conf      addValidatorsConfig
		operators []state.Operator
		errMsg    string
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
			operators: []state.Operator{op, op},
			errMsg:    "insufficient enr private key files",
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
			err := validateConf(tt.conf, tt.operators)
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
	const n = 3
	lock, p2pKeys, _ := cluster.NewForT(t, 1, n, n, 0)

	conf := addValidatorsConfig{
		NumVals:           1,
		WithdrawalAddrs:   []string{feeRecipientAddr},
		FeeRecipientAddrs: []string{feeRecipientAddr},
		TestConfig: TestConfig{
			Lock:    &lock,
			P2PKeys: p2pKeys,
		},
	}

	err := runAddValidatorsSolo(conf)
	require.NoError(t, err)
}
