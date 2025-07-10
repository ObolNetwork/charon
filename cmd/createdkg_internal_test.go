// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/testutil"
)

const validEthAddr = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359" // Taken from https://eips.ethereum.org/EIPS/eip-55

func TestCreateDkgValid(t *testing.T) {
	temp := t.TempDir()

	conf := createDKGConfig{
		OutputDir:         temp,
		NumValidators:     1,
		Threshold:         3,
		FeeRecipientAddrs: []string{validEthAddr},
		WithdrawalAddrs:   []string{validEthAddr},
		Network:           defaultNetwork,
		DKGAlgo:           "default",
		DepositAmounts:    []int{8, 16, 4, 4},
		ConsensusProtocol: "qbft",
		TargetGasLimit:    30000000,
		OperatorENRs: []string{
			"enr:-JG4QFI0llFYxSoTAHm24OrbgoVx77dL6Ehl1Ydys39JYoWcBhiHrRhtGXDTaygWNsEWFb1cL7a1Bk0klIdaNuXplKWGAYGv0Gt7gmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQL6bcis0tFXnbqG4KuywxT5BLhtmijPFApKCDJNl3mXFYN0Y3CCDhqDdWRwgg4u",
			"enr:-JG4QPnqHa7FU3PBqGxpV5L0hjJrTUqv8Wl6_UTHt-rELeICWjvCfcVfwmax8xI_eJ0ntI3ly9fgxAsmABud6-yBQiuGAYGv0iYPgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMLLCMZ5Oqi_sdnBfdyhmysZMfFm78PgF7Y9jitTJPSroN0Y3CCPoODdWRwgj6E",
			"enr:-JG4QDKNYm_JK-w6NuRcUFKvJAlq2L4CwkECelzyCVrMWji4YnVRn8AqQEL5fTQotPL2MKxiKNmn2k6XEINtq-6O3Z2GAYGvzr_LgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKlO7fSaBa3h48CdM-qb_Xb2_hSrJOy6nNjR0mapAqMboN0Y3CCDhqDdWRwgg4u",
			"enr:-JG4QKu734_MXQklKrNHe9beXIsIV5bqv58OOmsjWmp6CF5vJSHNinYReykn7-IIkc5-YsoF8Hva1Q3pl7_gUj5P9cOGAYGv0jBLgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMM3AvPhXGCUIzBl9VFOw7VQ6_m8dGifVfJ1YXrvZsaZoN0Y3CCDhqDdWRwgg4u",
		},
	}

	err := runCreateDKG(context.Background(), conf)
	require.NoError(t, err)
}

func TestCreateDkgInvalid(t *testing.T) {
	validENRs := []string{
		"enr:-JG4QFI0llFYxSoTAHm24OrbgoVx77dL6Ehl1Ydys39JYoWcBhiHrRhtGXDTaygWNsEWFb1cL7a1Bk0klIdaNuXplKWGAYGv0Gt7gmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQL6bcis0tFXnbqG4KuywxT5BLhtmijPFApKCDJNl3mXFYN0Y3CCDhqDdWRwgg4u",
		"enr:-JG4QPnqHa7FU3PBqGxpV5L0hjJrTUqv8Wl6_UTHt-rELeICWjvCfcVfwmax8xI_eJ0ntI3ly9fgxAsmABud6-yBQiuGAYGv0iYPgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMLLCMZ5Oqi_sdnBfdyhmysZMfFm78PgF7Y9jitTJPSroN0Y3CCPoODdWRwgj6E",
		"enr:-JG4QDKNYm_JK-w6NuRcUFKvJAlq2L4CwkECelzyCVrMWji4YnVRn8AqQEL5fTQotPL2MKxiKNmn2k6XEINtq-6O3Z2GAYGvzr_LgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKlO7fSaBa3h48CdM-qb_Xb2_hSrJOy6nNjR0mapAqMboN0Y3CCDhqDdWRwgg4u",
	}

	tests := []struct {
		conf   createDKGConfig
		errMsg string
	}{
		{
			conf: createDKGConfig{
				OperatorENRs: append([]string{
					"-JG4QDKNYm_JK-w6NuRcUFKvJAlq2L4CwkECelzyCVrMWji4YnVRn8AqQEL5fTQotPL2MKxiKNmn2k6XEINtq-6O3Z2GAYGvzr_LgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKlO7fSaBa3h48CdM-qb_Xb2_hSrJOy6nNjR0mapAqMboN0Y3CCDhqDdWRwgg4u",
				}, validENRs...),
				Threshold: 3,
				Network:   defaultNetwork,
			},
			errMsg: "invalid ENR: missing 'enr:' prefix",
		},
		{
			conf: createDKGConfig{
				OperatorENRs: append([]string{
					"enr:JG4QDKNYm_JK-w6NuRcUFKvJAlq2L4CwkECelzyCVrMWji4YnVRn8AqQEL5fTQotPL2MKxiKNmn2k6XEINtq-6O3Z2GAYGvzr_LgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKlO7fSaBa3h48CdM-qb_Xb2_hSrJOy6nNjR0mapAqMboN0Y3CCDhqDdWRwgg4u",
				}, validENRs...),
				Threshold: 3,
				Network:   defaultNetwork,
			},
			errMsg: "invalid ENR: invalid enr record, too few elements",
		},
		{
			conf: createDKGConfig{
				OperatorENRs: append([]string{
					"enrJG4QDKNYm_JK-w6NuRcUFKvJAlq2L4CwkECelzyCVrMWji4YnVRn8AqQEL5fTQotPL2MKxiKNmn2k6XEINtq-6O3Z2GAYGvzr_LgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKlO7fSaBa3h48CdM-qb_Xb2_hSrJOy6nNjR0mapAqMboN0Y3CCDhqDdWRwgg4u",
				}, validENRs...),
				Threshold: 3,
				Network:   defaultNetwork,
			},
			errMsg: "invalid ENR: missing 'enr:' prefix",
		},
		{
			conf: createDKGConfig{
				OperatorENRs: append([]string{
					"JG4QDKNYm_JK-w6NuRcUFKvJAlq2L4CwkECelzyCVrMWji4YnVRn8AqQEL5fTQotPL2MKxiKNmn2k6XEINtq-6O3Z2GAYGvzr_LgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKlO7fSaBa3h48CdM-qb_Xb2_hSrJOy6nNjR0mapAqMboN0Y3CCDhqDdWRwgg4u",
				}, validENRs...),
				Threshold: 3,
				Network:   defaultNetwork,
			},
			errMsg: "invalid ENR: missing 'enr:' prefix",
		},
		{
			conf:   createDKGConfig{OperatorENRs: []string{""}},
			errMsg: "number of operators is below minimum",
		},
		{
			conf:   createDKGConfig{},
			errMsg: "number of operators is below minimum",
		},
		{
			conf: createDKGConfig{
				OperatorENRs:      validENRs,
				Threshold:         3,
				Network:           defaultNetwork,
				ConsensusProtocol: "unreal",
			},
			errMsg: "unsupported consensus protocol",
		},
	}

	for _, test := range tests {
		t.Run(test.errMsg, func(t *testing.T) {
			err := runCreateDKG(context.Background(), test.conf)
			require.EqualError(t, err, test.errMsg)
		})
	}
}

func TestRequireOperatorENRFlag(t *testing.T) {
	tests := []struct {
		name string
		args []string
		err  string
	}{
		{
			name: "no operator ENRs",
			args: []string{"dkg"},
			err:  "required flag(s) \"operator-enrs\" not set",
		},
		{
			name: "operator ENRs less than threshold",
			args: []string{"dkg", "--operator-enrs=enr:-JG4QG472ZVvl8ySSnUK9uNVDrP_hjkUrUqIxUC75aayzmDVQedXkjbqc7QKyOOS71VmlqnYzri_taV8ZesFYaoQSIOGAYHtv1WsgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKwwq_CAld6oVKOrixE-JzMtvvNgb9yyI-_rwq4NFtajIN0Y3CCDhqDdWRwgg4u", "--fee-recipient-addresses=0xa6430105220d0b29688b734b8ea0f3ca9936e846", "--withdrawal-addresses=0xa6430105220d0b29688b734b8ea0f3ca9936e846"},
			err:  "number of operators is below minimum",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := newCreateCmd(newCreateDKGCmd(runCreateDKG))
			cmd.SetArgs(test.args)
			require.EqualError(t, cmd.Execute(), test.err)
		})
	}
}

func TestExistingClusterDefinition(t *testing.T) {
	charonDir := testutil.CreateTempCharonDir(t)
	b := []byte("sample definition")
	require.NoError(t, os.WriteFile(path.Join(charonDir, "cluster-definition.json"), b, 0o600))

	var enrs []string
	for range minNodes {
		enrs = append(enrs, "enr:-JG4QG472ZVvl8ySSnUK9uNVDrP_hjkUrUqIxUC75aayzmDVQedXkjbqc7QKyOOS71VmlqnYzri_taV8ZesFYaoQSIOGAYHtv1WsgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKwwq_CAld6oVKOrixE-JzMtvvNgb9yyI-_rwq4NFtajIN0Y3CCDhqDdWRwgg4u")
	}

	enrArg := "--operator-enrs=" + strings.Join(enrs, ",")
	feeRecipientArg := "--fee-recipient-addresses=" + validEthAddr
	withdrawalArg := "--withdrawal-addresses=" + validEthAddr
	outputDirArg := "--output-dir=" + charonDir
	thresholdArg := "--threshold=2"

	cmd := newCreateCmd(newCreateDKGCmd(runCreateDKG))
	cmd.SetArgs([]string{"dkg", enrArg, feeRecipientArg, withdrawalArg, outputDirArg, thresholdArg})

	require.EqualError(t, cmd.Execute(), "existing cluster-definition.json found. Try again after deleting it")
}

func TestValidateWithdrawalAddr(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		addrs := []string{validEthAddr}
		err := validateWithdrawalAddrs(addrs, eth2util.Goerli.Name)
		require.NoError(t, err)
	})

	t.Run("invalid network", func(t *testing.T) {
		err := validateWithdrawalAddrs([]string{zeroAddress}, eth2util.Mainnet.Name)
		require.ErrorContains(t, err, "zero address forbidden on this network")
	})

	t.Run("invalid withdrawal address", func(t *testing.T) {
		addrs := []string{"0xBAD000BAD000BAD"}
		err := validateWithdrawalAddrs(addrs, eth2util.Gnosis.Name)
		require.ErrorContains(t, err, "invalid withdrawal address")
	})

	t.Run("invalid checksum", func(t *testing.T) {
		addrs := []string{"0x000BAD0000000BAD0000000BAD0000000BAD0000"}
		err := validateWithdrawalAddrs(addrs, eth2util.Gnosis.Name)
		require.ErrorContains(t, err, "invalid checksummed address")
	})
}

func TestValidateDKGConfig(t *testing.T) {
	t.Run("insufficient ENRs", func(t *testing.T) {
		numOperators := 2
		err := validateDKGConfig(numOperators, "", nil, "", false)
		require.ErrorContains(t, err, "number of operators is below minimum")
	})

	t.Run("invalid network", func(t *testing.T) {
		numOperators := 4
		err := validateDKGConfig(numOperators, "cosmos", nil, "", false)
		require.ErrorContains(t, err, "unsupported network")
	})

	t.Run("wrong deposit amounts sum", func(t *testing.T) {
		err := validateDKGConfig(4, "goerli", []int{8, 16}, "", false)
		require.ErrorContains(t, err, "sum of partial deposit amounts must be at least 32ETH, repetition is allowed")
	})

	t.Run("unsupported consensus protocol", func(t *testing.T) {
		err := validateDKGConfig(4, "goerli", nil, "unreal", false)
		require.ErrorContains(t, err, "unsupported consensus protocol")
	})
}

func TestDKGCLI(t *testing.T) {
	var enrs []string
	for range minNodes {
		enrs = append(enrs, "enr:-JG4QG472ZVvl8ySSnUK9uNVDrP_hjkUrUqIxUC75aayzmDVQedXkjbqc7QKyOOS71VmlqnYzri_taV8ZesFYaoQSIOGAYHtv1WsgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKwwq_CAld6oVKOrixE-JzMtvvNgb9yyI-_rwq4NFtajIN0Y3CCDhqDdWRwgg4u")
	}

	enrArg := "--operator-enrs=" + strings.Join(enrs, ",")
	feeRecipientArg := "--fee-recipient-addresses=" + validEthAddr
	withdrawalArg := "--withdrawal-addresses=" + validEthAddr
	outputDirArg := "--output-dir=.charon"

	tests := []struct {
		name         string
		enr          string
		feeRecipient string
		withdrawal   string
		outputDir    string
		threshold    string
		expectedErr  string
		prepare      func(*testing.T)
		cleanup      func(*testing.T)
	}{
		{
			name:         "threshold below minimum",
			enr:          enrArg,
			feeRecipient: feeRecipientArg,
			withdrawal:   withdrawalArg,
			outputDir:    outputDirArg,
			threshold:    "--threshold=1",
			expectedErr:  "threshold must be greater than 1",
		},
		{
			name:         "threshold above maximum",
			enr:          enrArg,
			feeRecipient: feeRecipientArg,
			withdrawal:   withdrawalArg,
			outputDir:    outputDirArg,
			threshold:    "--threshold=4",
			expectedErr:  "threshold cannot be greater than number of operators",
		},
		{
			name:         "no threshold provided",
			enr:          enrArg,
			feeRecipient: feeRecipientArg,
			withdrawal:   withdrawalArg,
			outputDir:    outputDirArg,
			threshold:    "",
			expectedErr:  "",
			prepare: func(t *testing.T) {
				t.Helper()
				charonDir := testutil.CreateTempCharonDir(t)
				b := []byte("sample definition")
				require.NoError(t, os.WriteFile(path.Join(charonDir, "cluster-definition.json"), b, 0o600))
			},
			cleanup: func(t *testing.T) {
				t.Helper()
				err := os.RemoveAll(".charon")
				require.NoError(t, err)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.prepare != nil {
				test.prepare(t)
			}

			cmd := newCreateCmd(newCreateDKGCmd(runCreateDKG))
			if test.threshold != "" {
				cmd.SetArgs([]string{"dkg", test.enr, test.feeRecipient, test.withdrawal, test.outputDir, test.threshold})
			} else {
				cmd.SetArgs([]string{"dkg", test.enr, test.feeRecipient, test.withdrawal, test.outputDir})
			}

			err := cmd.Execute()
			if test.expectedErr != "" {
				require.ErrorContains(t, err, test.expectedErr)
			} else {
				require.NoError(t, err)
			}

			if test.cleanup != nil {
				test.cleanup(t)
			}
		})
	}
}
