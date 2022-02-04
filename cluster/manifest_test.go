// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cluster_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"net"
	"path"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/crypto"
)

func TestManifestJSON(t *testing.T) {
	// Create new random manifest.
	_, pubPoly := crypto.NewTBLSPoly(3)
	manifest := cluster.Manifest{
		TSS:     crypto.TBLSScheme{PubPoly: pubPoly},
		Members: make([]crypto.BLSPubkeyHex, 4),
		ENRs:    make([]string, 4),
	}
	for i := range manifest.Members {
		_, pubkey := crypto.NewKeyPair()
		manifest.Members[i] = crypto.BLSPubkeyHex{KyberG1: pubkey}
	}
	for i := range manifest.ENRs {
		manifest.ENRs[i] = newRandomENR(t)
	}
	// Check pubkey.
	dvPubkey := manifest.Pubkey()
	require.True(t, pubPoly.Commit().Equal(dvPubkey))
	// Check if ENRs work.
	records, err := manifest.ParsedENRs()
	require.NoError(t, err)
	require.Len(t, records, len(manifest.ENRs))
	// Marshal to JSON.
	data, err := json.MarshalIndent(&manifest, "", "\t")
	require.NoError(t, err)
	t.Log(crypto.BLSPointToHex(dvPubkey))
	t.Log(string(data))
	// Unmarshal from JSON.
	var manifest2 cluster.Manifest
	err = json.Unmarshal(data, &manifest2)
	require.NoError(t, err)
	// Marshal to JSON (again).
	data2, err := json.Marshal(&manifest2)
	require.NoError(t, err)
	// Check if result is the same.
	require.Equal(t, &manifest, &manifest2)
	require.JSONEq(t, string(data), string(data2))
}

func newRandomENR(t *testing.T) (res string) {
	t.Helper() // test helper function should start from t.Helper()
	privkey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	require.NoError(t, err)

	var r enr.Record

	r.Set(enr.IPv4(newRandomIP()))
	r.Set(enr.TCP(9877))
	r.SetSeq(1)

	err = enode.SignV4(&r, privkey)
	require.NoError(t, err)

	res, err = cluster.EncodeENR(&r)
	require.NoError(t, err)

	return
}

func newRandomIP() net.IP {
	buf := make([]byte, 4)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err.Error())
	}

	return buf
}

func TestDecodeENR_Equal(t *testing.T) {
	randEnr := newRandomENR(t)
	t.Log(randEnr)
	record, err := cluster.DecodeENR(randEnr)
	require.NoError(t, err)
	require.NotNil(t, record)
	reencodedEnr, err := cluster.EncodeENR(record)
	require.Equal(t, randEnr, reencodedEnr)
	require.NoError(t, err)
	record2, err := cluster.DecodeENR(reencodedEnr)
	require.NoError(t, err)
	require.NotNil(t, record2)
	require.Equal(t, record, record2)
}

func TestDecodeENR_InvalidBase64(t *testing.T) {
	record, err := cluster.DecodeENR("enr:###")
	require.Error(t, err)
	require.Contains(t, err.Error(), "illegal base64 data at input byte 0")
	require.Nil(t, record)
}

func TestDecodeENR_InvalidRLP(t *testing.T) {
	record, err := cluster.DecodeENR("enr:AAAAAAAA")
	require.Error(t, err)
	require.Contains(t, err.Error(), "rlp: expected List")
	require.Nil(t, record)
}

func TestDecodeENR_Oversize(t *testing.T) {
	record, err := cluster.DecodeENR("enr:-IS4QBnEa-Oftjk7-sGRAY7IrvL5YjATdcHbqR5l2aXX2M25CiawfwaXh0k9hm98dCfdnqhz9mE-BfemFdjuL9KtHqgBgmlkgnY0gmlwhB72zxGJc2VjcDI1NmsxoQMaK8SspTrUgB8IYVI3qDgFYsHymPVsWlvIW477kxaKUIN0Y3CCJpUAAAA=")
	require.Error(t, err)
	require.Contains(t, err.Error(), "leftover garbage bytes in ENR")
	require.Nil(t, record)
}

func TestLoadManifest(t *testing.T) {
	tests := []struct {
		Name    string
		Pubkey  string
		PeerIDs []string
	}{
		{
			Name:   "manifest1",
			Pubkey: "83def2bde67a3e02449ff109b4d53e0126222bdc7a911c3f5bec00a44e4ba9c548cd7c55e1ecdef549a270af11fccb9e",
			PeerIDs: []string{
				"16Uiu2HAmN9XKV2epcD4Y7BrL7kgjaRRC4cQBn7VogZM8vpTRviLt",
				"16Uiu2HAm21Jj8zSR8nwLuM1y1uwmzBnMSUWCJpavRw7sw7NpFsgW",
				"16Uiu2HAkyS44t64Wvne5v41rR2VA52qVhu8E3VoZgut6tLy68iWe",
				"16Uiu2HAmQhC3bKcVY4L43EtdjiA1AL1tXRdV8M7fMcp2zvaTTfC1",
			},
		},
		{
			Name:   "manifest2",
			Pubkey: "b2f1159d098209122eb5aabc64041d73ddcdbca05beec7a91c29e9f352a3a617443396cb571a121c40f6609b828b4375",
			PeerIDs: []string{
				"16Uiu2HAmAhqTGkApyjbJu4t3BUsoRkNcWfdfmBKCGRVsGeXeNUMA",
				"16Uiu2HAkxsCbWPqP42ivjv4tHLu4Fvyhow9xF6C4nf5f6HKBfXpR",
				"16Uiu2HAm9Bk5aXcfW17cV1nGLzcy145Wdh6td7oDWKJydvw9KLMp",
				"16Uiu2HAmLXFFnm3PQEJw3EJoqurbL3shnvaFGJbYC1FvsKf1Ntii",
			},
		},
		{
			Name:   "manifest3",
			Pubkey: "8637f84a6dab18fcb7114e4c8e8acf008e707712fa7c427433a56de1fcc4375f48ed925ad9bc5554a8596806adaa5606",
			PeerIDs: []string{
				"16Uiu2HAmJBzwzzTBdHP8ymN11jp5gLowStavef6sQ7YBSYRN21Xy",
				"16Uiu2HAmU9eYgaB31Zcnr4xLUx8AqAA2b3PxKBizhaX8pLaJk1uk",
				"16Uiu2HAm9fpYuh8uA5QDw4Ldn59zvRjxKyMgoN9mYhEtX1UVJKiw",
				"16Uiu2HAm9SsWMCeKWezFwrZ13mpNCreM4n99nCpir6fpWjqCgBBy",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			m, err := cluster.LoadManifest(path.Join("testdata", test.Name+".json"))
			require.NoError(t, err)

			pubkey := crypto.BLSPointToHex(m.Pubkey())
			require.Equal(t, test.Pubkey, pubkey)

			require.Len(t, m.ENRs, 4)

			peerIDs, err := m.PeerIDs()
			require.NoError(t, err)

			var ids []string
			for _, id := range peerIDs {
				ids = append(ids, id.String())
			}

			require.EqualValues(t, test.PeerIDs, ids)
		})
	}
}
