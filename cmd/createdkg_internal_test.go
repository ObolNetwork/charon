// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateDkgValid(t *testing.T) {
	temp := t.TempDir()

	conf := createDKGConfig{
		OutputDir:         temp,
		NumValidators:     1,
		Threshold:         3,
		FeeRecipientAddrs: []string{deadAddress},
		WithdrawalAddrs:   []string{deadAddress},
		Network:           defaultNetwork,
		DKGAlgo:           "default",
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
			conf: createDKGConfig{OperatorENRs: append([]string{
				"-JG4QDKNYm_JK-w6NuRcUFKvJAlq2L4CwkECelzyCVrMWji4YnVRn8AqQEL5fTQotPL2MKxiKNmn2k6XEINtq-6O3Z2GAYGvzr_LgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKlO7fSaBa3h48CdM-qb_Xb2_hSrJOy6nNjR0mapAqMboN0Y3CCDhqDdWRwgg4u",
			}, validENRs...)},
			errMsg: "invalid ENR: missing 'enr:' prefix",
		},
		{
			conf: createDKGConfig{OperatorENRs: append([]string{
				"enr:JG4QDKNYm_JK-w6NuRcUFKvJAlq2L4CwkECelzyCVrMWji4YnVRn8AqQEL5fTQotPL2MKxiKNmn2k6XEINtq-6O3Z2GAYGvzr_LgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKlO7fSaBa3h48CdM-qb_Xb2_hSrJOy6nNjR0mapAqMboN0Y3CCDhqDdWRwgg4u",
			}, validENRs...)},
			errMsg: "invalid ENR: invalid enr record, too few elements",
		},
		{
			conf: createDKGConfig{OperatorENRs: append([]string{
				"enrJG4QDKNYm_JK-w6NuRcUFKvJAlq2L4CwkECelzyCVrMWji4YnVRn8AqQEL5fTQotPL2MKxiKNmn2k6XEINtq-6O3Z2GAYGvzr_LgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKlO7fSaBa3h48CdM-qb_Xb2_hSrJOy6nNjR0mapAqMboN0Y3CCDhqDdWRwgg4u",
			}, validENRs...)},
			errMsg: "invalid ENR: missing 'enr:' prefix",
		},
		{
			conf: createDKGConfig{OperatorENRs: append([]string{
				"JG4QDKNYm_JK-w6NuRcUFKvJAlq2L4CwkECelzyCVrMWji4YnVRn8AqQEL5fTQotPL2MKxiKNmn2k6XEINtq-6O3Z2GAYGvzr_LgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKlO7fSaBa3h48CdM-qb_Xb2_hSrJOy6nNjR0mapAqMboN0Y3CCDhqDdWRwgg4u",
			}, validENRs...)},
			errMsg: "invalid ENR: missing 'enr:' prefix",
		},
		{
			conf:   createDKGConfig{OperatorENRs: []string{""}},
			errMsg: "insufficient operator ENRs (min = 4)",
		},
		{
			conf:   createDKGConfig{},
			errMsg: "insufficient operator ENRs (min = 4)",
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
			err:  "insufficient operator ENRs (min = 4)",
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
	outDir := ".charon"
	b := []byte("sample definition")
	require.NoError(t, os.Mkdir(".charon", 0o755))
	require.NoError(t, os.WriteFile(path.Join(outDir, "cluster-definition.json"), b, 0o600))
	defer func() {
		require.NoError(t, os.RemoveAll(outDir))
	}()

	cmd := newCreateCmd(newCreateDKGCmd(runCreateDKG))
	cmd.SetArgs([]string{"dkg", "--operator-enrs=enr:-JG4QG472ZVvl8ySSnUK9uNVDrP_hjkUrUqIxUC75aayzmDVQedXkjbqc7QKyOOS71VmlqnYzri_taV8ZesFYaoQSIOGAYHtv1WsgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKwwq_CAld6oVKOrixE-JzMtvvNgb9yyI-_rwq4NFtajIN0Y3CCDhqDdWRwgg4u", "--fee-recipient-addresses=0xa6430105220d0b29688b734b8ea0f3ca9936e846", "--withdrawal-addresses=0xa6430105220d0b29688b734b8ea0f3ca9936e846"})
	require.EqualError(t, cmd.Execute(), "existing cluster-definition.json found. Try again after deleting it")
}
