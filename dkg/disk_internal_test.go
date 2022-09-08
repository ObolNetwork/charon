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

package dkg

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
)

func TestFetchDefinition(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 1, 2, 3, 0)
	validDef := lock.Definition
	invalidDef := cluster.Definition{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimSpace(r.URL.Path) {
		case "/validDef":
			b, _ := validDef.MarshalJSON()
			_, _ = w.Write(b)
		case "/invalidDef":
			b, _ := invalidDef.MarshalJSON()
			_, _ = w.Write(b)
		}
	}))
	defer server.Close()

	tests := []struct {
		name    string
		url     string
		want    cluster.Definition
		wantErr bool
	}{
		{
			name:    "Fetch valid definition",
			url:     fmt.Sprintf("%s/%s", server.URL, "validDef"),
			want:    validDef,
			wantErr: false,
		},
		{
			name:    "Fetch invalid definition",
			url:     fmt.Sprintf("%s/%s", server.URL, "invalidDef"),
			want:    invalidDef,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fetchDefinition(context.Background(), tt.url)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.True(t, compareDefinitions(t, got, tt.want))
		})
	}
}

func TestLoadDefinition(t *testing.T) {
	// Valid definition
	lock, _, _ := cluster.NewForT(t, 1, 2, 3, 0)
	validDef := lock.Definition
	validFile := "valid-cluster-definition.json"
	b, err := json.MarshalIndent(validDef, "", " ")
	require.NoError(t, err)
	err = os.WriteFile(validFile, b, 0o666)
	require.NoError(t, err)

	// Invalid definition
	invalidDef := cluster.Definition{}
	invalidFile1 := "invalid-cluster-definition.json"
	err = os.WriteFile(invalidFile1, []byte{1, 2, 3}, 0o666)
	require.NoError(t, err)

	// Invalid definition without definition_hash and config_hash
	invalidFile2 := "invalid-cluster-definition2.json"
	defJSON := []byte(`{"name":"test cluster","operators":[{"address":"0x9A4C8145c7457b0BDC84Ba46729c3c9e15b56106","enr":"enr:-Iu4QFTSWOu_OplK-CYUv29EqIoMGQGtuHjTxLohMxOEMSxYFqraJdtWfMiwzS9wiGH-gB32IrYdyXSH-i5nJbLTm4yAgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQJ9hgLS0tOo-w3eLfoHVnENCJuN5QXDgtCX_cHQo5FpDoN0Y3CC52eDdWRwgudo","config_signature":"0x84b5e48201deebc59ac09c2aaec57870cad357d5a0b65a1954ee301b2760597d479a8ee2b6037963554b5323fb7944a389b9e86948ad89da08d6fffcc4ba5c5a01","enr_signature":"0x1530ab4bf5267f88c76850f9750e328698e0206f70a29bf2a6136cec3ffc365e620bddcd46ecfe667718dd6770b38c7c4c7bdf1e6c8ecaf0bc098d3959d9ae0c00"},{"address":"0x79AB788F445d5A689C34AD6e54e247865DE41E99","enr":"enr:-Iu4QDKAQ7dsqHud5m1T2FsjYcahgYRrzMiCZjjx9sRTOjnWH67n8ZEepVZ4WHp-XNn0c0CtFIB-KSBHeiKe8oDLztiAgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPFe0POIvtf3fkTXUjkj7yLDJ2APptRF6CK8_9C8g0NvYN0Y3CC52mDdWRwgudq","config_signature":"0xc8a306ec102a83dce35be9a552d0b30a09e74b1c1b2316596245c0e8f2ffa5d063051373993ecb694d82e2d65a398ecd5ef06599661903470385998d19a702f001","enr_signature":"0x61c44ee84dfc3991fe9de0d25f2bc3cad7feb0d3341208c894f455a233bcb1d2647b4fd29c376ceb2e5d2990fb2af7b6eae10bfe5b55963404ea2571222b350c01"},{"address":"0xfDdd1CF7733Fd8a638020e963792f9Fcc0182Bf4","enr":"enr:-Iu4QNgEtRy6wbpdPCXrj52_rF4Ur7OQf6mOg1xfRpmzPgRYW-QSA-oUslOTmIPL8etUIg95quQoRJg9FIILIa6990uAgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQLM5474DZHwbqwSbQFLrAO8PNh2AdZOXTYGy1ZItyDJaoN0Y3CC52uDdWRwguds","config_signature":"0xddb059b67e0603c0073536225e3a5ae5a7eeae178ec4c31dda521ed9b0209dc90b7e3295ee5ad4f35fbe0b8d62adf4aa4cfbddd3106f7563d234e0b134d9e93701","enr_signature":"0x3c556e60c4b44a4ea015f860759fa01e2e8664d105455b71e55845f451d7ec5e048ee56999c9f5333024bfcc087471fcb7d8e8a2685cb59d63266b4df092104501"}],"uuid":"04513690-AA41-CE01-6281-7901E9FB6D87","version":"v1.2.0","timestamp":"2022-09-07T18:46:30+05:30","num_validators":1,"threshold":2,"fee_recipient_address":"0xd805a5fcea20d3d27d3eee59d5dd5749e3271617","withdrawal_address":"0x75e896f172869cf3ade31c97f681cc1a4015ceed","dkg_algorithm":"default","fork_version":"0x00000000"}`)
	err = os.WriteFile(invalidFile2, defJSON, 0o666)
	require.NoError(t, err)
	var invalidDef2 cluster.Definition
	require.NoError(t, invalidDef2.UnmarshalJSON(defJSON))

	defer func() {
		require.NoError(t, os.Remove(validFile))
		require.NoError(t, os.Remove(invalidFile1))
		require.NoError(t, os.Remove(invalidFile2))
	}()

	tests := []struct {
		name     string
		defFile  string
		want     cluster.Definition
		noVerify bool
		wantErr  bool
	}{
		{
			name:     "Load valid definition",
			defFile:  validFile,
			want:     validDef,
			noVerify: false,
			wantErr:  false,
		},
		{
			name:     "Definition file doesn't exist",
			defFile:  "",
			want:     invalidDef,
			noVerify: false,
			wantErr:  true,
		},
		{
			name:     "Load invalid definition",
			defFile:  invalidFile1,
			want:     invalidDef,
			noVerify: false,
			wantErr:  true,
		},
		{
			name:     "Load invalid definition with no verify",
			defFile:  invalidFile2,
			want:     invalidDef2,
			noVerify: true,
			wantErr:  false,
		},
		{
			name:     "Load invalid definition without no verify",
			defFile:  invalidFile2,
			want:     invalidDef2,
			noVerify: false,
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := loadDefinition(context.Background(), Config{DefFile: tt.defFile, NoVerify: tt.noVerify})
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.True(t, compareDefinitions(t, got, tt.want))
		})
	}
}

func compareDefinitions(t *testing.T, a, b cluster.Definition) bool {
	t.Helper()

	b1, err := json.Marshal(a)
	require.NoError(t, err)

	b2, err := json.Marshal(b)
	require.NoError(t, err)

	return bytes.Equal(b1, b2)
}
