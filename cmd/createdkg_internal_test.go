// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateDkgValid(t *testing.T) {
	temp, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	conf := createDKGConfig{
		OutputDir:         temp,
		NumValidators:     1,
		Threshold:         3,
		FeeRecipient:      "",
		WithdrawalAddress: defaultWithdrawalAddr,
		Network:           defaultNetwork,
		DKGAlgo:           "default",
		OperatorENRs: []string{
			"enr:-JG4QFI0llFYxSoTAHm24OrbgoVx77dL6Ehl1Ydys39JYoWcBhiHrRhtGXDTaygWNsEWFb1cL7a1Bk0klIdaNuXplKWGAYGv0Gt7gmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQL6bcis0tFXnbqG4KuywxT5BLhtmijPFApKCDJNl3mXFYN0Y3CCDhqDdWRwgg4u",
			"enr:-JG4QPnqHa7FU3PBqGxpV5L0hjJrTUqv8Wl6_UTHt-rELeICWjvCfcVfwmax8xI_eJ0ntI3ly9fgxAsmABud6-yBQiuGAYGv0iYPgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMLLCMZ5Oqi_sdnBfdyhmysZMfFm78PgF7Y9jitTJPSroN0Y3CCPoODdWRwgj6E",
			"enr:-JG4QDKNYm_JK-w6NuRcUFKvJAlq2L4CwkECelzyCVrMWji4YnVRn8AqQEL5fTQotPL2MKxiKNmn2k6XEINtq-6O3Z2GAYGvzr_LgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKlO7fSaBa3h48CdM-qb_Xb2_hSrJOy6nNjR0mapAqMboN0Y3CCDhqDdWRwgg4u",
			"enr:-JG4QKu734_MXQklKrNHe9beXIsIV5bqv58OOmsjWmp6CF5vJSHNinYReykn7-IIkc5-YsoF8Hva1Q3pl7_gUj5P9cOGAYGv0jBLgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMM3AvPhXGCUIzBl9VFOw7VQ6_m8dGifVfJ1YXrvZsaZoN0Y3CCDhqDdWRwgg4u",
		},
	}

	err = runCreateDKG(context.Background(), conf)
	require.NoError(t, err)
}

func TestCreateDkgInvalid(t *testing.T) {
	tests := []struct {
		conf createDKGConfig
	}{
		{
			conf: createDKGConfig{OperatorENRs: []string{"-JG4QDKNYm_JK-w6NuRcUFKvJAlq2L4CwkECelzyCVrMWji4YnVRn8AqQEL5fTQotPL2MKxiKNmn2k6XEINtq-6O3Z2GAYGvzr_LgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKlO7fSaBa3h48CdM-qb_Xb2_hSrJOy6nNjR0mapAqMboN0Y3CCDhqDdWRwgg4u"}},
		},
		{
			conf: createDKGConfig{OperatorENRs: []string{"enr:JG4QDKNYm_JK-w6NuRcUFKvJAlq2L4CwkECelzyCVrMWji4YnVRn8AqQEL5fTQotPL2MKxiKNmn2k6XEINtq-6O3Z2GAYGvzr_LgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKlO7fSaBa3h48CdM-qb_Xb2_hSrJOy6nNjR0mapAqMboN0Y3CCDhqDdWRwgg4u"}},
		},
		{
			conf: createDKGConfig{OperatorENRs: []string{"enrJG4QDKNYm_JK-w6NuRcUFKvJAlq2L4CwkECelzyCVrMWji4YnVRn8AqQEL5fTQotPL2MKxiKNmn2k6XEINtq-6O3Z2GAYGvzr_LgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKlO7fSaBa3h48CdM-qb_Xb2_hSrJOy6nNjR0mapAqMboN0Y3CCDhqDdWRwgg4u"}},
		},
		{
			conf: createDKGConfig{OperatorENRs: []string{"JG4QDKNYm_JK-w6NuRcUFKvJAlq2L4CwkECelzyCVrMWji4YnVRn8AqQEL5fTQotPL2MKxiKNmn2k6XEINtq-6O3Z2GAYGvzr_LgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKlO7fSaBa3h48CdM-qb_Xb2_hSrJOy6nNjR0mapAqMboN0Y3CCDhqDdWRwgg4u"}},
		},
	}

	for _, test := range tests {
		t.Run("create dkg", func(t *testing.T) {
			err := runCreateDKG(context.Background(), test.conf)
			require.Error(t, err)
		})
	}
}
